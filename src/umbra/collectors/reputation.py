"""Reputation collectors — is this IP / domain known-bad?

Umbra's first free-tier tool. Aggregates multiple public threat-intel sources
into a single verdict, with **per-source provenance** — the point is a verdict
you can defend, each contributing source cited, not a black-box score.

Design:
- Multi-source, key-optional. Key-free sources (Spamhaus DNSBL, abuse.ch feeds,
  Tor list) give a usable answer with zero configuration; AbuseIPDB enriches
  when a key is set.
- Fail-open per source: one dead source records a note and is skipped, never
  fails the run.
- The verdict + score land in the entity's props; every responding source
  writes its own EvidenceIn.

Parsing and scoring live in pure functions (`parse_*`, `verdict_from_hits`) so
they are unit-testable without network. The collectors only wire fetch → parse.

See docs: Projects/OSINT/Umbra-Reputation-Feature in the vault.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.dns import DnsblResult, dnsbl_lookup
from umbra.core.models import CollectorResult, EntityIn, EntityType, EvidenceIn
from umbra.db.schema import Entity
from umbra.core.notes import describe_http_failure


# --- verdict model --------------------------------------------------------

@dataclass
class ReputationHit:
    """One source's contribution to the reputation verdict."""
    source: str
    listed: bool
    weight: float           # 0..1 confidence that "listed" means malicious
    detail: str
    url: str | None = None
    raw: dict[str, Any] | None = field(default=None)
    #: What the source actually listed.
    #:   "domain"  — the domain itself is on a blocklist (Spamhaus DBL)
    #:   "content" — a URL *hosted on* the domain was listed (URLhaus, ThreatFox)
    #:   "policy"  — a listing that is not an accusation (Spamhaus PBL: "this is
    #:               an end-user address"). Reported, never allowed to decide.
    #: Defaults to "domain", the conservative reading: a hit that does not say
    #: otherwise is treated as being about the host.
    scope: str = "domain"
    #: Whether the source actually answered. `listed=False` alone cannot say
    #: whether the source said *no* or could not be reached, and those are not
    #: the same claim. False means unchecked: no evidence either way.
    checked: bool = True


# Verdict thresholds on the weighted max signal.
_MALICIOUS_AT = 0.75
_SUSPICIOUS_AT = 0.30


# Sources belong to organisations. Four abuse.ch feeds agreeing is abuse.ch
# saying it once; Spamhaus and OpenPhish agreeing is two organisations.
# Measured 2026-09-01: only 17 of 9,223 abuse.ch hosts appear in more than one
# of its feeds (0.18%), because the feeds cover different things — malware
# URLs, C2 IOCs, banking trojans. They are complementary, not corroborating.
_PROVIDER = {
    "urlhaus": "abuse.ch",
    "threatfox": "abuse.ch",
    "feodo_tracker": "abuse.ch",
    "sslbl": "abuse.ch",
    "spamhaus_dbl": "spamhaus",
    "spamhaus_zen": "spamhaus",
    "openphish": "openphish",
    "abuseipdb": "abuseipdb",
}

#: Sources that describe a role rather than an accusation. Running a Tor exit
#: is not wrongdoing, and letting it combine would push an IP already at
#: spamhaus_zen 0.6 up to 0.70 — turning "suspicious" into "malicious" partly
#: because the address is an exit node. Reported, never counted.
_NON_ACCUSATORY = {"tor_exit", "tor_relay"}

#: Sources whose score is an **aggregate of third-party complaints** rather than
#: a specific finding about the host. The number is real; what it measures
#: depends on who the host is. On a Tor relay it mostly measures how much
#: traffic strangers pushed through it, so it is reported and not allowed to
#: decide — see `verdict_from_hits`. Everywhere else it decides normally.
_AGGREGATE_SOURCES = {"abuseipdb"}

#: The most any combination of sources may assert. Evidence accumulates; proof
#: does not arrive.
_CERTAINTY_CEILING = 0.99


def provider_of(source: str) -> str:
    """Which organisation this source belongs to.

    An unknown source is its own provider: a newly added feed must not
    silently join an existing group and start corroborating itself.
    """
    return _PROVIDER.get(source, source)


def combine_listed(listed: list[ReputationHit]) -> float:
    """Combined evidence strength from the sources that fired, in 0..1.

    Strongest feed within a provider, then **noisy-OR across providers**:

        combined = 1 - product over providers of (1 - w)

    So one source at 0.9 stays 0.9, while Spamhaus 0.7 and OpenPhish 0.85
    together reach 0.955 — three independent organisations agreeing used to
    score exactly the same as one, because `max` cannot express corroboration.

    **Not a probability, and deliberately not a Bayesian posterior.** A
    posterior needs a prior — the base rate of malicious domains among the
    things people actually paste into /reputation — and there is no honest way
    to estimate that. Noisy-OR needs no prior, stays bounded, and never
    decreases when evidence is added.
    """
    by_provider: dict[str, float] = {}
    for h in listed:
        if h.source in _NON_ACCUSATORY:
            continue
        p = provider_of(h.source)
        by_provider[p] = max(by_provider.get(p, 0.0), float(h.weight or 0.0))
    combined = 0.0
    for w in by_provider.values():
        combined = combined + w - (combined * w)
    # Never 1.0. Three providers agreeing reached exactly 100/100, and a score
    # of 100 claims certainty that no finite amount of third-party evidence
    # supports — the same overclaim this codebase refuses everywhere else.
    return min(_CERTAINTY_CEILING, combined)


def verdict_from_hits(hits: list[ReputationHit],
                      *, platform=None) -> tuple[str, int, list[str]]:
    """Aggregate source hits into (verdict, score 0-100, source-name list).

    Score is the strongest single listing signal scaled to 100 — deliberately
    "worst source wins" rather than an average, because one high-confidence C2
    or malware listing is decisive regardless of how many sources are clean.
    Absence of listings is reported as clean, never as proof of safety.

    `platform` is a `umbra.collectors.platforms.Platform` when the host is one
    where the public supplies the content. For those, **content-scope listings
    do not set the verdict**: a malware URL on GitHub is a fact about a file
    somebody uploaded, and letting it condemn the apex domain made the score a
    measure of popularity — github.com and drive.google.com both read
    "suspicious" in production while smaller hosts read clean.

    The listing is still returned in the source list. It is reported
    separately, not suppressed; only its authority over the verdict is removed.
    A domain-scope listing condemns a platform exactly as it would anyone else.
    """
    listed = [h for h in hits if h.listed]
    if not hits:
        return "unknown", 0, []
    if not listed:
        # Nothing fired — but "no source said yes" and "no source answered" are
        # different claims. An address whose every lookup errored used to come
        # back clean, which is the one thing this codebase refuses to say.
        if not any(h.checked for h in hits):
            return "unknown", 0, []
        return "clean", 0, []
    # A Tor relay's address collects community reports as a *baseline*: traffic
    # from thousands of strangers exits through it and the complaints land on
    # the relay. AbuseIPDB rates a busy exit at 100% for that reason alone, and
    # enabling the key turned "running a relay" into malicious 99/100 on its own
    # — the exact outcome `_NON_ACCUSATORY` was written to prevent, arriving
    # through a source that guard does not name.
    #
    # So an *aggregate* score cannot decide a verdict about a relay. A
    # *specific* listing still can: Feodo naming it as C2, or URLhaus serving
    # malware from it, is an accusation about this host and is untouched. The
    # distinction is the same one `platform` already draws — a malware URL on
    # GitHub is a fact about somebody's upload, not about GitHub.
    on_tor = any(h.source in _NON_ACCUSATORY for h in hits)

    deciding = [h for h in listed
                if not (platform is not None and h.scope == "content")
                # A policy listing (Spamhaus PBL) is a statement about what kind
                # of address this is, not about what it has done. Reported in
                # the source list below, never allowed to set a verdict.
                and h.scope != "policy"
                and not (on_tor and h.source in _AGGREGATE_SOURCES)
                and h.source not in _NON_ACCUSATORY]
    if not deciding:
        # Everything that fired was about content the public uploaded, or was a
        # role rather than an accusation. Reportable; not a verdict.
        return "clean", 0, [h.source for h in listed]
    top = combine_listed(deciding)
    score = int(round(top * 100))
    if top >= _MALICIOUS_AT:
        verdict = "malicious"
    elif top >= _SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "suspicious"  # any listing is at least suspicious
    return verdict, score, [h.source for h in listed]


# --- pure parsers (unit-tested without network) ---------------------------

def parse_abuseipdb(data: dict[str, Any]) -> ReputationHit:
    """AbuseIPDB /check response → hit. Score 0-100 maps to weight."""
    d = data.get("data", data)
    conf = float(d.get("abuseConfidenceScore", 0) or 0)
    reports = int(d.get("totalReports", 0) or 0)
    weight = conf / 100.0
    return ReputationHit(
        source="abuseipdb",
        listed=conf >= 25,
        weight=weight,
        detail=f"abuse confidence {conf:.0f}%, {reports} reports",
        url="https://www.abuseipdb.com/check/" + str(d.get("ipAddress", "")),
        raw=d,
    )


def parse_urlhaus_host(data: dict[str, Any]) -> ReputationHit:
    """URLhaus /v1/host response → hit."""
    status = data.get("query_status")
    if status != "ok":
        return ReputationHit("urlhaus", False, 0.0, "no URLhaus records")
    url_count = int(data.get("url_count", 0) or 0)
    urls = data.get("urls") or []
    online = sum(1 for u in urls if (u.get("url_status") == "online"))
    blacklists = set()
    for u in urls:
        for _bl, val in (u.get("blacklists") or {}).items():
            if val and val != "not listed":
                blacklists.add(_bl)
    # active malware URLs are high-confidence; historical-only is lower
    weight = 0.9 if online else (0.6 if url_count else 0.0)
    return ReputationHit(
        source="urlhaus",
        scope="content",
        listed=url_count > 0,
        weight=weight,
        detail=f"{url_count} malware URL(s), {online} online"
               + (f"; blacklisted: {', '.join(sorted(blacklists))}" if blacklists else ""),
        url="https://urlhaus.abuse.ch/browse.php?search=" + str(data.get("host", "")),
        raw=data,
    )


@dataclass(frozen=True)
class ZenClass:
    """What a set of Spamhaus Zen return codes actually means."""
    label: str
    weight: float
    #: True when every code is a policy listing (PBL) — see `_ZEN_CODES`.
    policy_only: bool


#: Spamhaus Zen return codes, their meaning, and how much each is worth.
#:
#: The weights were flat at 0.6 for every code. That made DROP — a hijacked
#: netblock Spamhaus tells you not to route — score identically to PBL, which
#: means "this is somebody's home internet connection".
#:
#: PBL carries weight 0.0 deliberately. It is a *policy* listing: it says an
#: address is end-user space that should not be delivering mail directly, which
#: is true of nearly every residential IP and is not evidence of anything.
_ZEN_CODES: dict[str, tuple[str, float]] = {
    "127.0.0.2": ("SBL — direct spam source", 0.60),
    "127.0.0.3": ("SBL CSS — snowshoe spam infrastructure", 0.50),
    "127.0.0.4": ("XBL — compromised device, open proxy or worm", 0.60),
    "127.0.0.5": ("XBL — compromised device, open proxy or worm", 0.60),
    "127.0.0.6": ("XBL — compromised device, open proxy or worm", 0.60),
    "127.0.0.7": ("XBL — compromised device, open proxy or worm", 0.60),
    "127.0.0.9": ("SBL DROP — hijacked or leased-to-criminals netblock", 0.85),
    "127.0.0.10": ("PBL — end-user address, should not send mail directly", 0.0),
    "127.0.0.11": ("PBL — end-user address, should not send mail directly", 0.0),
}

_PBL_CODES = {"127.0.0.10", "127.0.0.11"}


def classify_zen_codes(codes: list[str]) -> ZenClass:
    """Interpret Zen return codes into a label and a severity.

    The worst code decides. An address on both XBL and PBL is a compromised
    machine that happens to be residential — the compromise is the finding, and
    the residential part is context.

    An unrecognised code is reported verbatim at the default weight rather than
    guessed at. Spamhaus can add codes; inventing a meaning for one is worse
    than admitting the code is unfamiliar.
    """
    known = [c for c in codes if c in _ZEN_CODES]
    unknown = [c for c in codes if c not in _ZEN_CODES]

    parts = [_ZEN_CODES[c][0] for c in known]
    weight = max((_ZEN_CODES[c][1] for c in known), default=0.0)

    if unknown:
        parts.extend(f"unrecognised code {c}" for c in unknown)
        weight = max(weight, 0.60)

    policy_only = bool(codes) and not unknown and all(c in _PBL_CODES for c in codes)
    label = "; ".join(dict.fromkeys(parts)) or "listed"
    return ZenClass(label=label, weight=weight, policy_only=policy_only)


def dnsbl_hit(source: str, weight: float, zone: str, res: DnsblResult) -> ReputationHit:
    """Build a ReputationHit from a classified DNSBL result.

    Critically: a hit is `listed` ONLY when the result status is "listed".
    An "error" result (e.g. a `127.255.255.x` refusal from querying via a public
    resolver) is NOT a listing — it must not flag a clean address as malicious,
    which was the core bug in the previous DNS solution.

    An error is also not a *clean* result, which was the next bug: `checked`
    carries that distinction so scoring can tell "this source said no" from
    "this source never answered".

    For Spamhaus Zen the return codes decide both the wording and the weight;
    `weight` is the caller's default, used only where the codes say nothing
    more specific.
    """
    listed = res.status == "listed"
    checked = res.status in {"listed", "not_listed"}
    scope = "domain"
    hit_weight = 0.0

    if listed:
        if zone.endswith("zen.spamhaus.org"):
            zc = classify_zen_codes(list(res.codes))
            hit_weight = zc.weight
            scope = "policy" if zc.policy_only else "domain"
            detail = (f"listed in {zone}: {zc.label} "
                      f"({', '.join(res.codes)})")
            if zc.policy_only:
                # Said plainly, because "listed in Spamhaus" reads as an
                # accusation to every reader who has not memorised the codes.
                detail += " — a policy listing, not a report of abuse"
        else:
            hit_weight = weight
            detail = f"listed in {zone} ({', '.join(res.codes)})"
    elif res.status == "error":
        detail = f"{zone} check error: {res.detail}"
    else:
        detail = f"not listed in {zone}"

    return ReputationHit(
        source=source,
        listed=listed,
        weight=hit_weight,
        detail=detail,
        url="https://check.spamhaus.org/results/",
        scope=scope,
        checked=checked,
    )


def evidence_confidence(hit: ReputationHit) -> float:
    """Confidence to record on the evidence row for one source.

    Three states, not two. A source that could not be reached asserts nothing,
    and recording that at the same 0.5 as a confirmed negative is how "unchecked"
    became indistinguishable from "clean" in the collector users hit most.
    """
    if hit.listed:
        return hit.weight
    if not hit.checked:
        return 0.1
    return 0.5


# --- feed cache (download-once blocklists) --------------------------------

def _cache_get(cache_dir: Path, name: str, ttl_s: float) -> Any | None:
    p = cache_dir / name
    if not p.exists():
        return None
    if (time.time() - p.stat().st_mtime) > ttl_s:
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _cache_put(cache_dir: Path, name: str, value: Any) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / name).write_text(json.dumps(value))
    except Exception:
        pass


def _reverse_ipv4(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return ".".join(reversed(ip.split(".")))


# DNSBL lookups live in umbra.core.dns (dnsbl_lookup): local-resolver-only,
# no public failover, with return-code classification.


# --- collectors -----------------------------------------------------------

class IpReputationCollector(BaseCollector):
    name = "ip_reputation"
    timeout_s = 30
    version = "0.1.0"
    inputs = {EntityType.IP}
    description = "Aggregate IP reputation: Spamhaus ZEN, abuse.ch Feodo, AbuseIPDB (key), Tor exit"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        ip = entity.value.strip()
        result = CollectorResult()
        hits: list[ReputationHit] = []
        src_key = entity.norm_key
        timeout = ctx.settings.request_timeout_s

        # 1. Spamhaus ZEN (key-free DNSBL, IPv4 only)
        rev = _reverse_ipv4(ip)
        if rev:
            res = dnsbl_lookup(f"{rev}.zen.spamhaus.org", timeout)
            hit = dnsbl_hit("spamhaus_zen", 0.6, "zen.spamhaus.org", res)
            hits.append(hit)
            self._evidence(result, hit, src_key)
            if res.status == "error":
                result.notes.append(f"spamhaus_zen: {res.detail}")
        else:
            result.notes.append("spamhaus_zen: skipped (not IPv4)")

        # 2. abuse.ch Feodo Tracker (key-free, cached botnet C2 blocklist)
        try:
            feodo = self._feodo_set(ctx)
            listed = ip in feodo
            hit = ReputationHit(
                "feodo_tracker", listed, 0.95 if listed else 0.0,
                "known botnet C2" if listed else "not in Feodo C2 list",
                "https://feodotracker.abuse.ch/browse/",
            )
            hits.append(hit)
            self._evidence(result, hit, src_key)
        except Exception as exc:  # noqa: BLE001
            # Not f"...: {exc}". abuse.ch answers with HTTP 503 and the Varnish
            # reason phrase "certificate has expired" — their certificate is
            # valid, that is just the string on their error page. Interpolated
            # raw, the note read `feodo_tracker error: Server error '503
            # certificate has expired'` and sent the reader to debug TLS.
            result.notes.append(
                describe_http_failure(
                    "feodo_tracker", exc, "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
                )
            )

        # 3. AbuseIPDB (optional key)
        key = ctx.settings.abuseipdb_api_key
        if key:
            try:
                resp = ctx.http.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                hit = parse_abuseipdb(resp.json())
                hits.append(hit)
                self._evidence(result, hit, src_key)
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"abuseipdb error: {exc}")
        else:
            result.notes.append("abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)")

        # 4. Tor relay role, from the owned lake (context, never badness).
        #
        # This used to read the bulk *exit* list, which is 6,021 of the 15,794
        # relays in the consensus. A guard or middle relay produced no answer
        # at all, and no answer reads like a clean one — that is the bug an
        # operator reported after looking up an address that was plainly on a
        # Tor list.
        try:
            from umbra.lake.tor import TorLake, describe_flags

            tor_lake = TorLake.from_settings(ctx.settings)
            try:
                if not tor_lake.status()["synced"]:
                    result.notes.append(
                        "tor: relay lake never synced (run `umbra tor sync`) — "
                        "not checked, so this is unknown rather than not-a-relay"
                    )
                    relay = None
                else:
                    relay = tor_lake.lookup(ip)
            finally:
                tor_lake.close()

            if relay:
                role = ("exit" if relay["is_exit"]
                        else "guard" if relay["is_guard"] else "middle")
                # An exit can originate a connection to your service; a middle
                # relay cannot, so finding one in a log means something quite
                # different. Kept apart rather than collapsed into "Tor".
                detail = (
                    f"Tor {role} relay"
                    + (f" '{relay['nickname']}'" if relay.get("nickname") else "")
                    + f" — flags {', '.join(describe_flags(relay['flags'])) or relay['flags']}"
                    + (". Flagged BadExit by the directory authorities."
                       if relay["is_bad_exit"] else
                       ". Running a relay is not wrongdoing.")
                )
                hit = ReputationHit(
                    "tor_relay", True, 0.0, detail,
                    "https://metrics.torproject.org/rs.html#search/" + ip,
                    raw={"role": role, "flags": relay["flags"],
                         "nickname": relay.get("nickname"),
                         "bad_exit": bool(relay["is_bad_exit"])},
                )
                result.entities.append(EntityIn(
                    type=EntityType.IP, value=ip, confidence=0.9,
                    props={"tor_relay": True, "tor_role": role,
                           "tor_nickname": relay.get("nickname"),
                           "tor_flags": relay["flags"],
                           "tor_bad_exit": bool(relay["is_bad_exit"])},
                ))
                hits.append(hit)
                self._evidence(result, hit, src_key)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"tor lookup error: {exc}")

        self._apply_verdict(result, entity, EntityType.IP, ip, hits)
        return result

    def _feodo_set(self, ctx: CollectorContext) -> set[str]:
        cached = _cache_get(ctx.settings.cache_dir, "feodo_ipblocklist.json",
                            ctx.settings.reputation_feed_ttl_s)
        if cached is not None:
            return set(cached)
        resp = ctx.http.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        resp.raise_for_status()
        data = resp.json()
        ips = sorted({row.get("ip_address") for row in data if row.get("ip_address")})
        _cache_put(ctx.settings.cache_dir, "feodo_ipblocklist.json", ips)
        return set(ips)

    def _tor_set(self, ctx: CollectorContext) -> set[str]:
        cached = _cache_get(ctx.settings.cache_dir, "tor_exit_list.json",
                            ctx.settings.reputation_feed_ttl_s)
        if cached is not None:
            return set(cached)
        resp = ctx.http.get("https://check.torproject.org/torbulkexitlist")
        resp.raise_for_status()
        ips = sorted({ln.strip() for ln in resp.text.splitlines() if ln.strip()
                      and not ln.startswith("#")})
        _cache_put(ctx.settings.cache_dir, "tor_exit_list.json", ips)
        return set(ips)

    def _evidence(self, result: CollectorResult, hit: ReputationHit, key: str) -> None:
        result.evidence.append(EvidenceIn(
            collector=self.name,
            source_name=hit.source,
            source_url=hit.url,
            summary=hit.detail,
            confidence=evidence_confidence(hit),
            raw=hit.raw,
            entity_key=key,
        ))

    def _apply_verdict(self, result: CollectorResult, entity: Entity,
                       etype: EntityType, value: str, hits: list[ReputationHit]) -> None:
        from umbra.collectors.platforms import lookup_platform

        # Only domains can be user-content platforms; an IP is nobody's brand.
        platform = lookup_platform(value) if etype is EntityType.DOMAIN else None
        verdict, score, sources = verdict_from_hits(hits, platform=platform)

        props = {
            "reputation_verdict": verdict,
            "reputation_score": score,
            "reputation_sources": sources,
            "reputation_checked": len(hits),
        }
        content_listed = [h for h in hits if h.listed and h.scope == "content"]
        if platform:
            props["platform_label"] = platform.label
            props["platform_kind"] = platform.kind
            props["platform_caution"] = platform.caution
            props["hosted_threat_count"] = len(content_listed)
            props["hosted_threat_sources"] = [h.source for h in content_listed]
        result.entities.append(EntityIn(
            type=etype,
            value=value,
            confidence=max(0.9, entity.confidence),
            props=props,
        ))
        result.notes.append(
            f"reputation: {verdict} (score {score}, "
            f"{len(sources)}/{len(hits)} sources listed)"
        )
        if platform and content_listed:
            # Say why the verdict is not what the raw listings imply, on the
            # run itself — not only in the UI.
            result.notes.append(
                f"{value} is {platform.label}, where the public uploads the "
                f"content. {len(content_listed)} source(s) list malicious files "
                f"hosted here; that is reported separately and does not make the "
                f"site itself suspicious."
            )


class DomainReputationCollector(BaseCollector):
    name = "domain_reputation"
    timeout_s = 30
    version = "0.1.0"
    inputs = {EntityType.DOMAIN}
    description = "Aggregate domain reputation: URLhaus (abuse.ch) + Spamhaus DBL"

    # share the verdict/evidence helpers with the IP collector
    _evidence = IpReputationCollector._evidence
    _apply_verdict = IpReputationCollector._apply_verdict


    def _urlhaus_from_lake(self, host: str, ctx, result) -> ReputationHit | None:
        """URLhaus from the owned lake. None when the lake has never synced.

        None, not a clean hit: an unsynced lake knows nothing about every host
        equally, and reporting that as "not listed" is the failure this codebase
        exists to avoid.
        """
        try:
            from umbra.lake.store import LakeStore

            lake = LakeStore.from_settings(ctx.settings)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"urlhaus lake unreadable: {exc}")
            return None

        try:
            if not lake.abuse_feed_synced_at("urlhaus"):
                result.notes.append(
                    "urlhaus: never synced into this lake (run `umbra abuse sync`) — "
                    "not checked, so this is unknown rather than clean"
                )
                return None
            urls = lake.abuse_urls_for_host(host, limit=200)
        finally:
            close = getattr(lake, "close", None)
            if close:
                close()

        online = sum(1 for u in urls if (u.get("url_status") == "online"))
        return ReputationHit(
            source="urlhaus",
            scope="content",
            listed=bool(urls),
            # Live malware URLs are decisive; historical-only is weaker but real.
            weight=0.9 if online else (0.6 if urls else 0.0),
            detail=(f"{len(urls)} malware URL(s) in the owned lake, {online} online"
                    if urls else "not in the owned URLhaus corpus"),
            url="https://urlhaus.abuse.ch/browse.php?search=" + host,
        )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        domain = entity.value.strip().lower().rstrip(".")
        result = CollectorResult()
        hits: list[ReputationHit] = []
        src_key = entity.norm_key
        timeout = ctx.settings.request_timeout_s

        # 1. Spamhaus DBL (key-free DNSBL) — the zero-key baseline.
        # Classification (in core.dns) treats 127.0.1.255 and the 127.255.255.x
        # range as errors, not listings.
        res = dnsbl_lookup(f"{domain}.dbl.spamhaus.org", timeout)
        hit = dnsbl_hit("spamhaus_dbl", 0.7, "dbl.spamhaus.org", res)
        hits.append(hit)
        self._evidence(result, hit, src_key)
        if res.status == "error":
            result.notes.append(f"spamhaus_dbl: {res.detail}")

        # 2. OpenPhish community feed (key-free, cached) — phishing hosts
        try:
            phish = self._openphish_hosts(ctx)
            listed = domain in phish
            hit = ReputationHit(
                "openphish", listed, 0.85 if listed else 0.0,
                "host of a known phishing URL" if listed
                else "not in OpenPhish community feed",
                "https://openphish.com/",
            )
            hits.append(hit)
            self._evidence(result, hit, src_key)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"openphish error: {exc}")

        # 3. URLhaus — the OWNED lake first, the API only as enrichment.
        #
        # This used to go straight to urlhaus-api.abuse.ch, which has needed a
        # free Auth-Key since 2024. With no key it recorded "urlhaus: skipped"
        # and moved on — while `umbra abuse sync` was already pulling the full
        # URLhaus feed into the local lake on a 6h timer, where malware_infra
        # reads it with no key at all. The answer was on disk and the verdict
        # said it had not been checked.
        #
        # Owning the data is the point: the lake also survives abuse.ch being
        # down, which it was during this review.
        lake_hit = self._urlhaus_from_lake(domain, ctx, result)
        if lake_hit is not None:
            hits.append(lake_hit)
            self._evidence(result, lake_hit, src_key)

        auth = ctx.settings.abusech_auth_key
        if auth:
            try:
                resp = ctx.http.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": domain},
                    headers={"Auth-Key": auth},
                )
                resp.raise_for_status()
                hit = parse_urlhaus_host(resp.json())
                hit.source = "urlhaus_live"
                hits.append(hit)
                self._evidence(result, hit, src_key)
            except Exception as exc:  # noqa: BLE001
                result.notes.append(
                    describe_http_failure("urlhaus_live", exc,
                                          "https://urlhaus-api.abuse.ch/v1/host/")
                )

        self._apply_verdict(result, entity, EntityType.DOMAIN, domain, hits)
        return result

    def _openphish_hosts(self, ctx: CollectorContext) -> set[str]:
        from urllib.parse import urlparse

        cached = _cache_get(ctx.settings.cache_dir, "openphish_hosts.json",
                            ctx.settings.reputation_feed_ttl_s)
        if cached is not None:
            return set(cached)
        resp = ctx.http.get("https://openphish.com/feed.txt")
        resp.raise_for_status()
        hosts = sorted({
            (urlparse(ln.strip()).hostname or "").lower()
            for ln in resp.text.splitlines() if ln.strip()
        } - {""})
        _cache_put(ctx.settings.cache_dir, "openphish_hosts.json", hosts)
        return set(hosts)
