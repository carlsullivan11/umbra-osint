"""Shodan InternetDB — read the index, scan nobody.

`umbra scan ports` sends packets, and `docs/PORT-SCAN.md` is mostly about when
it refuses: `public_cti` and `other` are denied outright, because finding an
address in a malware feed gives you no authority over it.

That refusal is why this collector exists in this shape. InternetDB answers the
same question — what is exposed on this address — out of Shodan's *existing*
index. No API key, no packet from Umbra to the target, so it is available on
every authorization basis precisely because it is not a scan. Nothing here may
become a way to obtain scan results without the gate: the only host this module
ever contacts is `internetdb.shodan.io`.

**Shodan's record is not our finding, and a miss is not an all-clear.** Shodan
scans on its own schedule and misses hosts; a 404 is the *normal* answer for an
address it has never indexed. Reporting that as "no open ports" would hand back
a scan result nobody was authorised to produce and that nobody produced. Every
piece of copy here says whose scan it was and when it was fetched, because a
record with no date is indistinguishable from a fresh one.

IPv4 only — InternetDB does not serve IPv6 — and public unicast only. A private,
loopback, link-local or CGNAT address is skipped rather than looked up: CGNAT in
particular is the carrier's address shared with other subscribers, so it is not
the investigated party's to ask about (same reasoning as `/exposure/ports`).
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import (
    CollectorResult,
    EntityIn,
    EntityType,
    EvidenceIn,
)
from umbra.db.schema import Entity
from umbra.ip_corpus import is_public_ip

logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

#: A host with 200 CVEs is usually an unpatched appliance, and listing them all
#: buries the run. The count is always reported even when the list is trimmed.
MAX_VULNS = 15

#: Said on every hit. An operator reading "3 open ports" on a case they never
#: scanned must not conclude that Umbra scanned it.
PROVENANCE = (
    "Shodan InternetDB, not our scan: this is Shodan's own index of what it "
    "observed, fetched without sending anything to the address."
)

_ARRAY_FIELDS = ("ports", "hostnames", "cpes", "tags", "vulns")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _skip_reason(value: str) -> str | None:
    """Why this address must not be looked up, or None if it may be."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return f"{value!r} is not an IP address"
    if ip.version != 4:
        return (
            "IPv6 is not served by Shodan InternetDB, so this address was not "
            "looked up. That is unchecked, not an absence of exposure."
        )
    if not is_public_ip(str(ip)):
        # CGNAT is the interesting one: 100.64.0.0/10 is the carrier's space,
        # shared between subscribers, so it is not the investigated party's
        # address to ask about — the same reasoning /exposure/ports uses.
        return (
            f"{ip} is not a public unicast address (private, loopback, "
            "link-local, reserved or carrier-NAT), so it was not looked up."
        )
    return None


class InternetDbCollector(BaseCollector):
    name = "internetdb"
    timeout_s = 15
    version = "0.1.0"
    inputs = {EntityType.IP}
    description = (
        "Read Shodan's InternetDB index for an IPv4 address — ports, hostnames, "
        "CPEs, tags and CVEs Shodan already observed (no key, no scan)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        value = (entity.value or "").strip()

        skip = _skip_reason(value)
        if skip:
            result.notes.append(f"internetdb: {skip}")
            return result

        url = INTERNETDB_URL.format(ip=value)
        try:
            resp = ctx.http.get(
                url, headers={"Accept": "application/json"}, timeout=self.timeout_s
            )
        except Exception as exc:  # noqa: BLE001
            from umbra.core.notes import describe_http_failure

            result.notes.append(describe_http_failure("internetdb", exc, url))
            return result

        if resp.status_code == 404:
            # The normal answer for a host Shodan has never indexed. It says
            # nothing whatsoever about what is listening.
            result.notes.append(
                f"internetdb: Shodan has no record of {value}. Shodan scans on "
                "its own schedule and does not see every host, and Umbra did "
                "not scan the address — so this is unchecked, not an absence "
                "of open ports."
            )
            return result

        if resp.status_code == 429:
            result.notes.append(
                "internetdb: rate limited (HTTP 429) — Shodan's index was not "
                "read, so this is unchecked rather than empty."
            )
            return result

        if resp.status_code >= 400:
            result.notes.append(
                f"internetdb: lookup failed (HTTP {resp.status_code}) — "
                "unchecked, not an absence of exposure."
            )
            return result

        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            logger.warning("internetdb: unparseable response for %s", value)
            result.notes.append(
                "internetdb: the response was not valid JSON — unchecked, not "
                "an absence of exposure."
            )
            return result

        if not isinstance(payload, dict):
            result.notes.append(
                "internetdb: unexpected response shape — unchecked."
            )
            return result

        fetched_at = _now()
        props: dict[str, object] = {"internetdb_fetched_at": fetched_at}
        counts: dict[str, int] = {}

        for field in _ARRAY_FIELDS:
            raw = payload.get(field)
            if not isinstance(raw, list) or not raw:
                # Absent rather than an empty list. Shodan reporting no ports
                # is Shodan's observation, and writing `[]` onto the entity
                # would render as a checked, confident "nothing open".
                continue
            counts[field] = len(raw)
            values = raw[:MAX_VULNS] if field == "vulns" else raw
            props[f"internetdb_{field}"] = values

        if len(payload.get("vulns") or []) > MAX_VULNS:
            # Never a silent cap.
            result.notes.append(
                f"internetdb: Shodan lists {counts['vulns']} CVE(s) for {value}; "
                f"the first {MAX_VULNS} are recorded."
            )

        result.entities.append(
            EntityIn(
                type=EntityType.IP,
                value=value,
                confidence=0.9,
                props=props,
            )
        )

        ports = props.get("internetdb_ports") or []
        bits = []
        if ports:
            bits.append(f"{len(ports)} port(s) observed: "
                        + ", ".join(str(p) for p in ports[:12]))
        if counts.get("vulns"):
            bits.append(f"{counts['vulns']} CVE(s) associated")
        if not bits:
            bits.append("a record exists but lists no ports, hostnames or CVEs")

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="Shodan InternetDB (free index, no scan by Umbra)",
                source_url=url,
                summary=(
                    f"Shodan InternetDB has a record for {value} — "
                    + "; ".join(bits)
                    + f". {PROVENANCE}"
                ),
                confidence=0.65,
                raw={
                    "ip": value,
                    "internetdb_fetched_at": fetched_at,
                    "ports": props.get("internetdb_ports"),
                    "hostnames": props.get("internetdb_hostnames"),
                    "cpes": props.get("internetdb_cpes"),
                    "tags": props.get("internetdb_tags"),
                    "vulns": props.get("internetdb_vulns"),
                    "vuln_count": counts.get("vulns", 0),
                    "source": "internetdb.shodan.io",
                },
                entity_key=entity.norm_key,
            )
        )

        result.notes.append(
            f"internetdb: {PROVENANCE} Shodan's record dates from whenever it "
            f"last looked, which may not be recent; fetched {fetched_at}."
        )
        if counts.get("vulns"):
            # A CPE-derived CVE list is an inference from a version banner, not
            # a confirmed finding, and it is the field most likely to be read
            # as one.
            result.notes.append(
                "internetdb: Shodan's CVE list is inferred from observed "
                "product versions, not verified exploitation — treat it as a "
                "lead to confirm, not a confirmed vulnerability."
            )
        return result
