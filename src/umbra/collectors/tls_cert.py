"""Pull certificate SANs by completing a real TLS handshake — no CT API.

Also records **how** the peer answered that same handshake: negotiated TLS
version, cipher suite, and ALPN. Those are already on the wire — the connection
is made either way — so keeping them costs no extra request, no extra port and
no extra collector. The count stays 40.

**ALPN is offered on the existing ClientHello.** `selected_alpn_protocol()`
returns None unless ALPN was advertised, so the one hello we already send now
lists `h2, http/1.1`. That is a different hello, not an additional one; opening
a second connection to vary the hello (JARM) is deliberately out of scope.

**A fingerprint is not an identity.** Everything behind Cloudflare negotiates
like Cloudflare, because to a TLS handshake it *is* Cloudflare. Shared hosting
collides the same way. These props describe a connection, never an owner.

**A miss is unchecked.** A refused handshake writes no `fp_*` key at all,
rather than a null that renders as a finding.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

#: Offered on the handshake we already make, so the server has something to
#: select. Ordered as a normal browser would: h2 preferred, http/1.1 fallback.
_ALPN_OFFER = ["h2", "http/1.1"]

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.http_guard import allow_private_egress, is_public_ip, resolve_all
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, normalize_value
from umbra.db.schema import Entity


def guard_host(host: str) -> str | None:
    """Why this host must not be connected to, or None if it may be.

    This collector opens `socket.create_connection` directly rather than going
    through `GuardedClient`, so AGENTS.md §2 — *collector egress goes through
    `umbra.core.http_guard`* — was not actually being enforced on this path.
    That was survivable while only authorized CLI and case runs reached it. It
    stops being survivable the moment an anonymous visitor supplies the host.

    Fails closed: a name that resolves to nothing was not checked, so it is
    refused rather than tried.
    """
    if allow_private_egress():
        return None
    addrs = resolve_all(host)
    if not addrs:
        return f"{host} did not resolve; refusing to connect"
    for addr in addrs:
        if not is_public_ip(addr):
            return f"{host} resolves to non-public address {addr}"
    return None


def _connection_facts(ssock) -> dict[str, object]:
    """What the peer negotiated, omitting anything it did not tell us.

    Every key here is conditional on purpose. A server that negotiates no ALPN
    has told us nothing about HTTP/2, and writing `fp_http2: False` for it
    would turn silence into a claim.
    """
    facts: dict[str, object] = {}
    try:
        version = ssock.version()
    except Exception:  # noqa: BLE001
        version = None
    if version:
        facts["fp_tls_version"] = version

    try:
        cipher = ssock.cipher()
    except Exception:  # noqa: BLE001
        cipher = None
    if cipher and cipher[0]:
        facts["fp_tls_cipher"] = cipher[0]

    try:
        alpn = ssock.selected_alpn_protocol()
    except Exception:  # noqa: BLE001
        alpn = None
    if alpn:
        facts["fp_alpn"] = alpn
        facts["fp_http2"] = alpn == "h2"
    return facts


class TlsCertCollector(BaseCollector):
    name = "tls_cert"
    timeout_s = 20
    inputs = {EntityType.DOMAIN}
    description = "Live TLS cert SANs/issuer via handshake (CT API substitute)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        host = entity.value.strip(".")
        src = entity.norm_key
        port = 443
        timeout = min(10.0, ctx.settings.request_timeout_s)

        blocked = guard_host(host)
        if blocked:
            result.notes.append(f"tls_cert: {blocked}")
            return result

        fp: dict[str, object] = {}
        try:
            ctx_ssl = ssl.create_default_context()
            # we want the cert even if hostname mismatch / expired for OSINT
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            try:
                ctx_ssl.set_alpn_protocols(_ALPN_OFFER)
            except (NotImplementedError, AttributeError):
                # Builds without ALPN still hand back a usable cert; the ALPN
                # props simply stay absent, which is the honest outcome.
                pass
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    der = ssock.getpeercert(binary_form=True)
                    fp = _connection_facts(ssock)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"tls_cert: {exc}")
            return result

        # When verify_mode is CERT_NONE, getpeercert() dict may be empty — parse DER
        sans: list[str] = []
        subject_cn = None
        issuer = None
        not_after = None
        serial = None
        fingerprint = None
        fingerprint_sha1 = None

        if der:
            try:
                from hashlib import sha1, sha256

                fingerprint = sha256(der).hexdigest()
                # SSLBL joins on SHA-1; keep it on the cert entity so sslbl_cert
                # can look up without re-fetching the DER.
                fingerprint_sha1 = sha1(der).hexdigest()
            except Exception:
                pass

        if cert:
            for tup in cert.get("subject", ()):
                for k, v in tup:
                    if k == "commonName":
                        subject_cn = v
            iss_parts = []
            for tup in cert.get("issuer", ()):
                for k, v in tup:
                    if k in {"organizationName", "commonName"}:
                        iss_parts.append(v)
            issuer = ", ".join(iss_parts) if iss_parts else None
            not_after = cert.get("notAfter")
            serial = cert.get("serialNumber")
            for typ, val in cert.get("subjectAltName", ()) or ():
                if typ == "DNS" and val:
                    sans.append(val.lower().lstrip("*."))

        # Fallback DER parse with ssl._ssl if dict empty
        if not sans and der:
            try:
                import tempfile
                import subprocess
                from pathlib import Path

                # openssl x509 parse if available
                p = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
                    input=der,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                text = p.stdout.decode("utf-8", "replace")
                for line in text.splitlines():
                    if "DNS:" in line:
                        for part in line.split(","):
                            part = part.strip()
                            if part.startswith("DNS:"):
                                sans.append(part[4:].strip().lower().lstrip("*."))
                    if "Subject:" in line and "CN=" in line:
                        subject_cn = line.split("CN=", 1)[-1].split(",")[0].strip()
                    if "Issuer:" in line:
                        issuer = line.split("Issuer:", 1)[-1].strip()[:200]
                    if "Not After" in line:
                        not_after = line.split(":", 1)[-1].strip()
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"openssl parse: {exc}")

        apex = normalize_value(EntityType.DOMAIN, host)
        for name in sorted(set(sans + ([subject_cn.lower().lstrip("*.")] if subject_cn else []))):
            if not name or " " in name:
                continue
            try:
                d = normalize_value(EntityType.DOMAIN, name)
            except ValueError:
                continue
            result.entities.append(EntityIn(type=EntityType.DOMAIN, value=d, confidence=0.85))
            if d != apex:
                result.edges.append(
                    EdgeIn(
                        source_key=entity_key(EntityType.DOMAIN, d),
                        target_key=src,
                        rel=EdgeType.ASSOCIATED_WITH,
                        confidence=0.7,
                        props={"via": "tls_san"},
                    )
                )

        # The seed carries the connection facts too: a reader asking "what is
        # this host running" is looking at the domain, not at a cert hash.
        if fp:
            result.entities.append(
                EntityIn(
                    type=EntityType.DOMAIN,
                    value=apex,
                    confidence=0.9,
                    props=dict(fp),
                )
            )

        if fingerprint:
            result.entities.append(
                EntityIn(
                    type=EntityType.CERT,
                    value=fingerprint,
                    confidence=0.9,
                    props={
                        "subject_cn": subject_cn,
                        "issuer": issuer,
                        "not_after": not_after,
                        "serial": serial,
                        "sans": sorted(set(sans))[:50],
                        "source": "live_tls",
                        "fingerprint_sha256": fingerprint,
                        "fingerprint_sha1": fingerprint_sha1,
                        "sha1": fingerprint_sha1,
                        **fp,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.CERT, fingerprint),
                    target_key=src,
                    rel=EdgeType.ISSUED_FOR,
                    confidence=0.9,
                )
            )
            if issuer:
                # Prefer O= organization from issuer string
                org_name = None
                if "O = " in issuer:
                    org_name = issuer.split("O = ", 1)[1].split(",", 1)[0].strip()
                elif "O=" in issuer:
                    org_name = issuer.split("O=", 1)[1].split(",", 1)[0].strip()
                if org_name and len(org_name) > 2 and "=" not in org_name:
                    result.entities.append(
                        EntityIn(type=EntityType.ORG, value=org_name[:120], confidence=0.45)
                    )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="TLS handshake",
                source_url=f"https://{host}/",
                summary=f"TLS cert for {host}: CN={subject_cn} SANs={len(set(sans))} issuer={issuer}",
                confidence=0.9,
                raw={
                    "subject_cn": subject_cn,
                    "issuer": issuer,
                    "not_after": not_after,
                    "sans": sorted(set(sans)),
                    "sha256": fingerprint,
                    "sha1": fingerprint_sha1,
                },
                entity_key=src,
            )
        )
        return result
