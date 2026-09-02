"""Multi-factor entity confidence scoring.

Combines:
- seed / verification overrides
- base collector confidence
- distinct evidence collectors
- graph degree (inbound/outbound edges)
- corroborating same_as / multi-edge support
- collector trust weights
- type priors

Writes `entity.confidence` and `props.score_breakdown`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from umbra.db.repository import Repository
from umbra.db.schema import Edge, Entity, Evidence

# Relative trust of collectors (0-1). Unknown collectors default to 0.55.
COLLECTOR_TRUST: dict[str, float] = {
    "dns_resolve": 0.9,
    "dns_email_auth": 0.85,
    "rdap_domain": 0.85,
    "rdap_ip": 0.8,
    "asn_cymru": 0.9,
    # City/country from owned DB-IP City Lite lake — useful but approximate.
    "ip_geo": 0.7,
    "tls_cert": 0.9,
    "crtsh": 0.8,
    "http_probe": 0.75,
    "tech_fingerprint": 0.7,
    "html_links": 0.65,
    "security_txt": 0.85,
    "email_split": 0.95,
    "gravatar": 0.7,
    "github_user": 0.85,
    "github_commits": 0.8,
    "username_presence": 0.45,  # high false-positive rate alone
    "wayback_cdx": 0.7,
    "ddg_search": 0.35,  # weak association
    "public_records_portals": 0.5,  # portals only
    "county_records": 0.45,  # allowlisted public GET; name-token ≠ identity
    # Lower than the rest of the person sources on purpose: a court record names
    # defendants who were acquitted and everyone who shares their name, so a hit
    # is a lead to confirm rather than a fact to score up.
    "court_records": 0.35,
    "wifi_maps": 0.4,  # crowdsourced last-seen / OSM cameras; not a residence
    "sex_offender_registry": 0.55,  # public registry; first+last on page ≠ identity
    # Obituary URLs + survivor name parse — useful graph, weak identity until confirm
    "obituary_search": 0.45,
    "hibp_breach": 0.95,
    "edgar_search": 0.55,
    "opencorporates": 0.5,
    "lookalike_domains": 0.75,  # resolved lookalike is meaningful
    "ip_reputation": 0.85,  # multi-source threat-intel aggregation, worst-source-wins
    "domain_reputation": 0.85,  # same aggregation model, domain-scoped
    "ransomware_exposure": 0.9,  # exact match against a validated public leak-site index
    "ct_lake": 0.9,  # locally-ingested, cryptographically-anchored CT data (owned corpus)
    "mac_oui": 0.9,  # the IEEE registry itself, read from the owned OUI lake
    # Offline numbering-plan only — high trust for format/region, not identity.
    "phone_validate": 0.9,
    # OFAC/curated lake exact address match — high trust that the *list* says
    # this, not that the operator is guilty.
    "crypto_screen": 0.9,
    # Curated, sourced, community-maintained — but anyone can edit it, and
    # most claims carry no reference at all. Good context, not ground truth.
    "wikidata": 0.7,
    # Reads the owned CVE corpus (CISA KEV + NVD imports), refreshed daily by
    # CI. Authoritative source, no external call, no key.
    "cve_lookup": 0.9,
    "malware_infra": 0.85,  # abuse.ch community reports, curated
    "sslbl_cert": 0.9,  # an exact fingerprint match, nothing fuzzy about it
}

# Soft prior by entity type when little else is known
TYPE_PRIOR: dict[str, float] = {
    "domain": 0.5,
    "ip": 0.55,
    "email": 0.5,
    "url": 0.4,
    "username": 0.4,
    "org": 0.45,
    "person": 0.35,
    "cert": 0.6,
    "asn": 0.7,
    "location": 0.55,
    "repo": 0.65,
    "technology": 0.5,
    "breach": 0.85,
    "nameserver": 0.6,
    "registrar": 0.6,
    "mac": 0.6,  # a concrete observed identifier, but L2-scoped
    "location": 0.5,  # a place name is context, not an identifier
    "vulnerability": 0.75,  # a CVE id is authoritative and globally unique
    "malware": 0.7,  # a curated family name; aliasing keeps it below a CVE
    "phone": 0.55,
    "crypto_address": 0.5,
}

# Relationship types that strongly corroborate an entity
STRONG_RELS = {
    "resolves_to",
    "has_ns",
    "has_mx",
    "registered_by",
    "issued_for",
    "uses_email",
    "exposed_in",
    "security_contact",
    "owns",
    "member_of",
    "same_as",
    "lookalike_of",
    "subdomain_of",
}


@dataclass
class ScoreResult:
    entity_id: str
    norm_key: str
    old: float
    new: float
    band: str
    breakdown: dict[str, Any] = field(default_factory=dict)


def band_for(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    if score >= 0.35:
        return "low"
    return "speculative"


def _clamp(x: float, lo: float = 0.01, hi: float = 0.99) -> float:
    return max(lo, min(hi, x))


def score_entity(
    ent: Entity,
    *,
    evidence_by_entity: dict[str, list[Evidence]],
    edges_in: dict[str, list[Edge]],
    edges_out: dict[str, list[Edge]],
    collectors_by_entity: dict[str, set[str]],
) -> tuple[float, dict[str, Any]]:
    """Return (score, breakdown)."""
    verification = (getattr(ent, "verification", None) or "unknown").lower()

    # Always gather collector set for transparency
    evs = evidence_by_entity.get(ent.id, [])
    collectors = set(collectors_by_entity.get(ent.id, set()))
    for ev in evs:
        if ev.collector:
            collectors.add(ev.collector)

    if verification == "false":
        return 0.05, {
            "override": "verification_false",
            "band": "speculative",
            "factors": {"verification": "false"},
            "collectors": sorted(collectors),
            "n_collectors": len(collectors),
            "n_evidence": len(evs),
            "verification": verification,
            "is_seed": bool(ent.is_seed),
        }
    if verification == "true":
        return 0.97, {
            "override": "verification_true",
            "band": "high",
            "factors": {"verification": "true"},
            "collectors": sorted(collectors),
            "n_collectors": len(collectors),
            "n_evidence": len(evs),
            "verification": verification,
            "is_seed": bool(ent.is_seed),
        }

    base = float(ent.confidence or TYPE_PRIOR.get(ent.type, 0.45))
    prior = TYPE_PRIOR.get(ent.type, 0.45)

    trust_vals = [COLLECTOR_TRUST.get(c, 0.55) for c in collectors]
    max_trust = max(trust_vals) if trust_vals else 0.4
    mean_trust = sum(trust_vals) / len(trust_vals) if trust_vals else 0.4
    n_collectors = len(collectors)

    # Graph support
    ein = edges_in.get(ent.id, [])
    eout = edges_out.get(ent.id, [])
    strong_in = sum(1 for e in ein if e.rel in STRONG_RELS)
    strong_out = sum(1 for e in eout if e.rel in STRONG_RELS)
    degree = len(ein) + len(eout)
    same_as = sum(1 for e in ein + eout if e.rel == "same_as")

    # Factors → additive model then clamp
    factors: dict[str, float] = {
        "base": base * 0.35,
        "type_prior": prior * 0.15,
        "max_collector_trust": max_trust * 0.2,
        "mean_collector_trust": mean_trust * 0.1,
        "multi_collector": min(0.15, 0.04 * max(0, n_collectors - 1)),
        "evidence_count": min(0.1, 0.02 * len(evs)),
        "strong_edges": min(0.12, 0.025 * (strong_in + strong_out)),
        "degree": min(0.06, 0.008 * degree),
        "same_as": min(0.08, 0.04 * same_as),
        "seed_boost": 0.12 if ent.is_seed else 0.0,
    }

    # Lookalike resolved domains: boost if lookalike_of edge exists and has IPs
    props = ent.props or {}
    if props.get("lookalike_of") and props.get("resolved_ips"):
        factors["lookalike_resolved"] = 0.08
    if props.get("hibp_breached") is True:
        factors["hibp"] = 0.1
    if props.get("gravatar_avatar") is True:
        factors["gravatar"] = 0.05

    # Penalties
    if n_collectors == 0 and not ent.is_seed and degree <= 1:
        factors["orphan_penalty"] = -0.12
    if ent.type == "username" and n_collectors <= 1 and "username_presence" in collectors:
        factors["username_single_probe_penalty"] = -0.15
    if ent.type in {"url", "person"} and n_collectors <= 1 and not ent.is_seed:
        factors["weak_type_penalty"] = -0.08
    if verification == "disputed":
        factors["disputed_penalty"] = -0.2

    score = _clamp(sum(factors.values()))
    breakdown = {
        "band": band_for(score),
        "factors": {k: round(v, 4) for k, v in factors.items()},
        "collectors": sorted(collectors),
        "n_collectors": n_collectors,
        "n_evidence": len(evs),
        "degree": degree,
        "strong_edges": strong_in + strong_out,
        "verification": verification,
        "is_seed": bool(ent.is_seed),
    }
    return score, breakdown


def build_indexes(repo: Repository, case_id: str) -> dict[str, Any]:
    entities = repo.list_entities(case_id, include_merged=True)
    edges = repo.list_edges(case_id)
    evidence = repo.list_evidence(case_id)

    evidence_by_entity: dict[str, list[Evidence]] = defaultdict(list)
    collectors_by_entity: dict[str, set[str]] = defaultdict(set)
    for ev in evidence:
        if ev.entity_id:
            evidence_by_entity[ev.entity_id].append(ev)
            if ev.collector:
                collectors_by_entity[ev.entity_id].add(ev.collector)

    # Also attribute collectors via edge props / evidence summaries lightly:
    # any evidence on case mentioning entity key in raw is already linked by entity_id.

    edges_in: dict[str, list[Edge]] = defaultdict(list)
    edges_out: dict[str, list[Edge]] = defaultdict(list)
    for e in edges:
        edges_out[e.source_id].append(e)
        edges_in[e.target_id].append(e)

    # Corroboration: if multiple edges of different rels touch entity, already in degree.

    # Also infer collectors from edge relationships when evidence isn't linked
    REL_COLLECTOR_HINT = {
        "lookalike_of": "lookalike_domains",
        "resolves_to": "dns_resolve",
        "has_mx": "dns_resolve",
        "has_ns": "dns_resolve",
        "member_of": "asn_cymru",
        "issued_for": "tls_cert",
        "security_contact": "security_txt",
        "exposed_in": "hibp_breach",
        "uses_tech": "tech_fingerprint",
        "subdomain_of": "crtsh",
    }
    for e in edges:
        hint = REL_COLLECTOR_HINT.get(e.rel)
        if not hint:
            continue
        collectors_by_entity[e.source_id].add(hint)
        collectors_by_entity[e.target_id].add(hint)

    return {
        "entities": entities,
        "evidence_by_entity": evidence_by_entity,
        "edges_in": edges_in,
        "edges_out": edges_out,
        "collectors_by_entity": collectors_by_entity,
    }


def score_case(repo: Repository, case_id: str, persist: bool = True) -> list[ScoreResult]:
    idx = build_indexes(repo, case_id)
    results: list[ScoreResult] = []

    for ent in idx["entities"]:
        if getattr(ent, "merged_into_id", None):
            continue
        old = float(ent.confidence or 0)
        new, breakdown = score_entity(
            ent,
            evidence_by_entity=idx["evidence_by_entity"],
            edges_in=idx["edges_in"],
            edges_out=idx["edges_out"],
            collectors_by_entity=idx["collectors_by_entity"],
        )
        results.append(
            ScoreResult(
                entity_id=ent.id,
                norm_key=ent.norm_key,
                old=old,
                new=new,
                band=breakdown["band"],
                breakdown=breakdown,
            )
        )
        if persist:
            ent.confidence = new
            props = dict(ent.props or {})
            props["score_breakdown"] = breakdown
            props["score_band"] = breakdown["band"]
            ent.props = props

    if persist:
        repo.audit(
            case_id,
            "case.score",
            {
                "entities": len(results),
                "high": sum(1 for r in results if r.band == "high"),
                "medium": sum(1 for r in results if r.band == "medium"),
                "low": sum(1 for r in results if r.band == "low"),
                "speculative": sum(1 for r in results if r.band == "speculative"),
            },
        )
        repo.session.commit()

    results.sort(key=lambda r: r.new, reverse=True)
    return results


def render_score_report(results: list[ScoreResult], case_id: str) -> str:
    lines = [
        f"# Confidence scores — `{case_id}`",
        "",
        f"Entities scored: **{len(results)}**",
        "",
        "| Band | Count |",
        "|------|------:|",
    ]
    for b in ("high", "medium", "low", "speculative"):
        lines.append(f"| {b} | {sum(1 for r in results if r.band == b)} |")
    lines.append("")
    lines.append("## Top entities")
    lines.append("")
    for r in results[:40]:
        delta = r.new - r.old
        lines.append(
            f"- `{r.norm_key}` — **{r.new:.2f}** ({r.band}) "
            f"Δ{delta:+.2f} collectors={r.breakdown.get('n_collectors')}"
        )
    lines.append("")
    lines.append("## Speculative / weak (review)")
    lines.append("")
    weak = [r for r in results if r.band in {"low", "speculative"}][:30]
    if not weak:
        lines.append("_None_")
    for r in weak:
        lines.append(f"- `{r.norm_key}` — {r.new:.2f} ({r.band})")
    lines.append("")
    lines.append("_Scoring is heuristic. Use `umbra entity verify` to lock truth._")
    return "\n".join(lines)
