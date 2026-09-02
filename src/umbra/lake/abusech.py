"""Owned abuse.ch lake — malware URLs, C2 IOCs and blacklisted certificates.

Rank 4 of `references/open-knowledge-sources.md`. The plan
(`references/abusech-collectors.md`) asks for three collectors that query
URLhaus, MalwareBazaar and SSLBL. This keeps the sources and changes where they
are read from, for two reasons that are visible in the code we already have:

**The API needs a key; the bulk download does not.** `domain_reputation` calls
`urlhaus-api.abuse.ch/v1/host/`, which has required a free Auth-Key since 2024,
so on an instance without one it has been reporting `urlhaus: skipped` on every
run. The bulk exports below are open, so owning the data turns a permanently
skipped source into a working one *and* removes a network call from the hot
path.

**The recent windows are a moving target.** These endpoints serve a rolling
window (URLhaus ~30 days, ThreatFox a few days). A lake that keeps what it has
already seen therefore grows past what abuse.ch will hand you today. That is the
difference between owning the data and proxying it, and it is why sync upserts
rather than replaces.

Everything here is parse-only or fetch-and-store; the query side lives on
`LakeStore` next to the CT corpus, and the collectors that read it never touch
the network.

MalwareBazaar is deliberately not ingested — see `docs/COLLECTORS.md`. It is
keyed by file hash, and nothing in an Umbra graph produces a file hash, so the
collector would never fire.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

FEEDS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}

# A feed download is a few megabytes of text; anything beyond this is a sign the
# endpoint changed shape rather than that the data grew.
MAX_FEED_BYTES = 64 * 1024 * 1024

# Trailing words in an SSLBL listing reason that name the *role* rather than the
# family: "Vidar C&C" is Vidar acting as a controller.
_ROLE_WORDS = ("C&C", "C2", "CnC", "Botnet", "Malware")


@dataclass
class MalwareUrl:
    url: str
    host: str
    added: str = ""
    status: str = ""
    threat: str = ""
    tags: str = ""
    reporter: str = ""
    reference: str = ""


@dataclass
class Ioc:
    """One indicator, from any feed. ThreatFox and Feodo share this shape."""

    feed: str
    ioc: str
    host: str
    ioc_type: str = ""
    threat_type: str = ""
    malware: str = ""
    confidence: int = 0
    tags: str = ""
    first_seen: str = ""
    reference: str = ""


@dataclass
class BadCert:
    sha1: str
    reason: str
    malware: str = ""
    listed_at: str = ""


def _host_of(value: str) -> str:
    """The bare hostname a lookup will use — no scheme, no port, no case."""
    text = (value or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        # `ip:port` from ThreatFox. IPv6 literals are bracketed, so a lone colon
        # is a port and a bare `::` is an address.
        if text.count(":") == 1:
            text = text.split(":", 1)[0]
    return text.strip().strip(".").lower()


def _rows(text: str) -> list[list[str]]:
    """CSV rows with the abuse.ch banner comments removed.

    The exports quote every field and separate with `", "` in some feeds and
    `","` in others; `skipinitialspace` covers both.
    """
    body = "\n".join(line for line in (text or "").splitlines()
                     if line and not line.lstrip().startswith("#"))
    if not body.strip():
        return []
    return [r for r in csv.reader(io.StringIO(body), skipinitialspace=True) if r]


def parse_urlhaus(text: str) -> list[MalwareUrl]:
    """`id,dateadded,url,url_status,last_online,threat,tags,link,reporter`."""
    out: list[MalwareUrl] = []
    for row in _rows(text):
        if len(row) < 7:
            continue
        url = row[2].strip()
        host = _host_of(url)
        if not url or not host:
            continue
        out.append(MalwareUrl(
            url=url, host=host, added=row[1].strip(), status=row[3].strip(),
            threat=row[5].strip(), tags=row[6].strip(),
            reference=row[7].strip() if len(row) > 7 else "",
            reporter=row[8].strip() if len(row) > 8 else "",
        ))
    return out


def parse_threatfox(text: str) -> list[Ioc]:
    """`first_seen,ioc_id,ioc,ioc_type,threat_type,malware,alias,printable,…`.

    `malware_printable` is used over `fk_malware` because "ClearFake" is what an
    analyst recognises and `js.clearfake` is an internal key.
    """
    out: list[Ioc] = []
    for row in _rows(text):
        if len(row) < 10:
            continue
        ioc = row[2].strip()
        host = _host_of(ioc)
        if not ioc or not host:
            continue
        try:
            confidence = int(row[9].strip() or 0)
        except ValueError:
            confidence = 0
        out.append(Ioc(
            feed="threatfox", ioc=ioc, host=host, ioc_type=row[3].strip(),
            threat_type=row[4].strip(),
            malware=(row[7].strip() or row[5].strip()),
            confidence=confidence, first_seen=row[0].strip(),
            tags=row[12].strip() if len(row) > 12 else "",
            reference=row[11].strip() if len(row) > 11 else "",
        ))
    return out


def parse_sslbl(text: str) -> list[BadCert]:
    """`Listingdate,SHA1,Listingreason` — the reason names the malware family."""
    out: list[BadCert] = []
    for row in _rows(text):
        if len(row) < 3:
            continue
        sha1 = row[1].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{4,64}", sha1):
            continue
        reason = row[2].strip()
        out.append(BadCert(sha1=sha1, reason=reason,
                           malware=_family_of(reason), listed_at=row[0].strip()))
    return out


def _family_of(reason: str) -> str:
    words = (reason or "").split()
    while words and words[-1] in _ROLE_WORDS:
        words.pop()
    return " ".join(words) or reason


def parse_feodo(text: str) -> list[Ioc]:
    """Feodo Tracker's botnet C2 blocklist, flattened into the IOC shape."""
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except Exception:  # noqa: BLE001 - a broken feed is not a crash
        logger.warning("feodo feed is not JSON")
        return []
    out: list[Ioc] = []
    for row in data if isinstance(data, list) else []:
        ip = str(row.get("ip_address") or "").strip()
        if not ip:
            continue
        port = row.get("port")
        out.append(Ioc(
            feed="feodo", ioc=f"{ip}:{port}" if port else ip, host=ip.lower(),
            ioc_type="ip:port" if port else "ip", threat_type="botnet_cc",
            malware=str(row.get("malware") or ""),
            confidence=100 if row.get("status") == "online" else 50,
            first_seen=str(row.get("first_seen") or ""),
            tags=str(row.get("status") or ""),
            reference="https://feodotracker.abuse.ch/browse/host/%s/" % ip,
        ))
    return out


_PARSERS = {
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "sslbl": parse_sslbl,
    "feodo": parse_feodo,
}


@dataclass
class SyncReport:
    counts: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def sync(store, http, feeds: list[str] | None = None) -> dict[str, int]:
    """Fetch the feeds and upsert them into the lake. Returns rows per feed.

    Each feed is independent: an abuse.ch outage on one download must not cost
    the other three, and a feed that failed is *not* marked as synced — a
    collector reading the lake needs to tell "checked and clean" from "never
    checked".
    """
    counts: dict[str, int] = {}
    for name in (feeds or list(FEEDS)):
        url = FEEDS.get(name)
        if not url:
            continue
        try:
            # follow_redirects=True so GuardedClient re-validates each hop (plain
            # httpx would need the same for abuse.ch CDN hops).
            resp = http.get(url, follow_redirects=True)
            resp.raise_for_status()
            body = resp.text
            if len(body.encode("utf-8", "ignore")) > MAX_FEED_BYTES:
                raise ValueError(f"{name} feed is implausibly large")
            rows = _PARSERS[name](body)
            counts[name] = store.abuse_upsert(name, rows)
        except Exception as exc:  # noqa: BLE001 - one feed down is not a failure
            logger.warning("abuse.ch %s sync failed: %s", name, exc)
            counts[name] = 0
    return counts
