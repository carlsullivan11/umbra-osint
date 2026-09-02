from __future__ import annotations

import time

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, normalize_value, parent_domain
from umbra.db.schema import Entity


class CrtshCollector(BaseCollector):
    name = "crtsh"
    timeout_s = 60
    inputs = {EntityType.DOMAIN}
    description = "Certificate Transparency via crt.sh (multi-query + retry)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        domain = entity.value
        result = CollectorResult()
        url = "https://crt.sh/"
        queries = [f"%.{domain}", domain, f"%{domain}%"]
        data: list = []
        last_err = None
        last_status: int | None = None
        # crt.sh 502s often — a server error means "we could not check", which is
        # a different answer from "this domain has no certificates". Conflating
        # them is the same failure as a DNSBL error rendering as "clean".
        unavailable = False

        for q in queries:
            for attempt in range(3):
                try:
                    resp = ctx.http.get(
                        url,
                        params={"q": q, "output": "json"},
                        timeout=max(25.0, ctx.settings.request_timeout_s),
                    )
                    last_status = resp.status_code
                    if resp.status_code == 200 and resp.content.strip():
                        payload = resp.json()
                        if isinstance(payload, list):
                            unavailable = False
                            if payload:
                                data = payload
                            break
                    if resp.status_code >= 500 or resp.status_code == 429:
                        # Retry the same query with real backoff rather than
                        # moving on: a different query string will not fix a
                        # struggling server.
                        unavailable = True
                        last_err = f"HTTP {resp.status_code}"
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    unavailable = False
                    last_err = f"status={resp.status_code}"
                    break
                except Exception as exc:  # noqa: BLE001
                    unavailable = True
                    last_err = f"{type(exc).__name__}: {exc}"[:120]
                    time.sleep(1.5 * (attempt + 1))
            if data or unavailable:
                # Three query variants against a failing service is six requests
                # for nothing; stop asking.
                break

        if not data:
            if unavailable:
                result.notes.append(
                    f"crt.sh unavailable for {domain} ({last_err}) — this is NOT "
                    f"'no certificates'; the source could not be reached. The owned "
                    f"corpus (`ct_lake`) is unaffected."
                )
            else:
                result.notes.append(f"crt.sh returned no certificates for {domain}")
            # soft success evidence so pipeline knows we tried
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="crt.sh",
                    source_url=f"https://crt.sh/?q={domain}",
                    summary=(f"crt.sh unavailable for {domain} — not checked"
                             if unavailable else
                             f"crt.sh returned no certificates for {domain}"),
                    confidence=0.3,
                    # `available` is the field that lets a later reader tell a
                    # negative result from an unanswered question.
                    raw={"error": last_err, "available": not unavailable,
                         "status": last_status, "queries_tried": queries},
                    entity_key=entity.norm_key,
                )
            )
            return result

        src_key = entity.norm_key
        seen: set[str] = set()
        names: set[str] = set()
        for row in data[:500]:
            name_value = row.get("name_value") or ""
            for part in str(name_value).split("\n"):
                host = part.strip().lower().lstrip("*.")
                if not host or " " in host:
                    continue
                if not (host == domain or host.endswith("." + domain)):
                    continue
                names.add(host)
            # Identity: the serial, matching the owned lake, so the same
            # certificate seen through either path is the same node. This used
            # to be `sha256 or id` — and crt.sh returns no sha256, so it was in
            # practice a crt.sh row id masquerading as a fingerprint.
            #
            # No fingerprint is claimed here: getting a real one means fetching
            # and hashing each certificate, which is one extra request per cert
            # against a rate-limited free service that already times out under
            # load. `ct_lake` computes it properly at ingest, from the DER.
            serial = row.get("serial_number")
            crtsh_id = row.get("id")
            cert_value = str(serial or crtsh_id or "").strip()
            if cert_value and cert_value not in seen:
                seen.add(cert_value)
                issuer = (row.get("issuer_name") or "").strip()
                result.entities.append(
                    EntityIn(
                        type=EntityType.CERT,
                        value=cert_value,
                        confidence=0.75,
                        props={
                            "issuer": issuer or None,
                            "cn": row.get("common_name"),
                            "serial_number": serial,
                            "not_before": row.get("not_before"),
                            "not_after": row.get("not_after"),
                            "crtsh_id": crtsh_id,
                            "source": "crt.sh",
                        },
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=entity_key(EntityType.CERT, cert_value),
                        target_key=src_key,
                        rel=EdgeType.ISSUED_FOR,
                        confidence=0.75,
                    )
                )
                if issuer:
                    # Same relationship ct_lake emits, so the two CT paths agree.
                    result.entities.append(
                        EntityIn(type=EntityType.ORG, value=issuer, confidence=0.7,
                                 props={"role": "certificate_issuer", "source": "crt.sh"})
                    )
                    result.edges.append(
                        EdgeIn(source_key=entity_key(EntityType.CERT, cert_value),
                               target_key=entity_key(EntityType.ORG, issuer),
                               rel=EdgeType.ISSUED_FOR, confidence=0.7,
                               props={"role": "issuer", "source": "crt.sh"})
                    )

        apex = normalize_value(EntityType.DOMAIN, domain)
        for host in sorted(names)[:200]:
            result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.8))
            hkey = entity_key(EntityType.DOMAIN, host)
            if host != apex:
                result.edges.append(
                    EdgeIn(
                        source_key=hkey,
                        target_key=src_key,
                        rel=EdgeType.SUBDOMAIN_OF,
                        confidence=0.85,
                    )
                )
            parent = parent_domain(host)
            if parent and parent != host:
                result.entities.append(EntityIn(type=EntityType.DOMAIN, value=parent, confidence=0.7))
                result.edges.append(
                    EdgeIn(
                        source_key=hkey,
                        target_key=entity_key(EntityType.DOMAIN, parent),
                        rel=EdgeType.PARENT_DOMAIN,
                        confidence=0.7,
                    )
                )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="crt.sh",
                source_url=f"https://crt.sh/?q={domain}",
                summary=f"CT: {len(names)} hostnames, {len(seen)} certs for {domain}",
                confidence=0.8,
                raw={"count": len(data), "hostnames": sorted(names)[:200]},
                entity_key=src_key,
            )
        )
        return result
