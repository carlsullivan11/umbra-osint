"""Enrich an alert's external indicators, ask Jev, and decide.

Enrichment is Umbra's ordinary depth-0 run on a case, the same path the public
reputation page takes, minus every collector that would **contact the
indicator** (`ACTIVE_COLLECTORS`). Probing a suspected C2 from the analyst's
own machine tips off whoever runs it and puts the analyst's address in their
logs. `active=True` puts them back for an operator who wants that.

Jev sees Umbra's facts and the alert's context. It never sees the listing
(which `decide()` handles deterministically, and which the thresholds were
fitted without), internal addresses, host names or user names.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from umbra.core.models import EntityIn, EntityType
from umbra.jev.client import Answer, JevClient, JevUnavailable
from umbra.jev.facts import Facts, count_words, facts_from_props, render_state
from umbra.jev.questions import INJECTION_CANARY, INJECTION_CANARY_KEY, SOC_TRIAGE
from umbra.triage.alert import Alert, Indicator
from umbra.triage.disposition import Decision, decide, worst

#: The collector whose evidence rows are owned abuse.ch lake hits, and where
#: `enrich()` puts them on the props it returns.
LAKE_COLLECTOR = "malware_infra"
LAKE_HITS = "_abuse_lake_hits"

#: Collectors that open a connection to the host being assessed.
ACTIVE_COLLECTORS = frozenset({"http_probe", "tech_fingerprint", "tls_cert", "security_txt",
                               "html_links", "cve_lookup"})

#: How far p(malware_or_c2) may fall when the untrusted text is added before
#: the fall is read as manipulation (same bar as umbra.jev.adjudicate).
BENIGN_SHIFT_AT = 0.25

#: Facts the listing contributes. Withheld from Jev: listings are decided in
#: code, and the fitted thresholds assume Jev never saw them.
_LISTING_FACTS = ("blocklists listing it", "blocklists consulted")

_ALERT_TYPE = {
    "outbound_conn": "firewall: internal host opened an outbound connection",
    "dns_query": "DNS log: internal host resolved a domain",
    "web_request": "web proxy: internal host requested a URL",
    "inbound_conn": "external address connected to or requested something from our systems",
    "indicator": "indicator submitted for triage (no alert context)",
}


@dataclass
class IndicatorResult:
    indicator: Indicator
    decision: Decision
    listing: str = "unknown"
    listed_by: list[str] = field(default_factory=list)
    state: str = ""
    error: str | None = None
    model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {**self.indicator.to_dict(), "listing": self.listing, "listed_by": self.listed_by,
                **self.decision.to_dict(), "error": self.error, "model": self.model}


@dataclass
class AlertResult:
    alert: Alert
    disposition: str
    indicators: list[IndicatorResult] = field(default_factory=list)
    case_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"alert": self.alert.to_dict(), "disposition": self.disposition,
                "case_id": self.case_id,
                "indicators": [r.to_dict() for r in self.indicators]}


def triage_collectors(types: set[EntityType], *, active: bool = False) -> list[str]:
    from umbra.intent.plan import select_collectors
    from umbra.intent.schema import IntentFlags, IntentSeed

    names: list[str] = []
    for t in sorted(types, key=lambda x: x.value):
        seed = IntentSeed(type=t, value="placeholder", confidence=0.95, include=True)
        for c in select_collectors([seed], IntentFlags()) or []:
            if c not in names and (active or c not in ACTIVE_COLLECTORS):
                names.append(c)
    return names


def enrich(alerts: list[Alert], repo: Any, *, basis: str, active: bool = False,
           max_seconds: float = 90.0) -> tuple[str, dict[tuple[str, str], dict[str, Any]]]:
    """One case for the whole batch; returns (case_id, props by indicator)."""
    from umbra.core.orchestrator import Orchestrator

    unique: dict[tuple[str, str], Indicator] = {}
    for a in alerts:
        for ind in a.indicators:
            unique.setdefault((ind.type.value, ind.value), ind)
    first = next(iter(unique.values())).value if unique else "empty"
    case = repo.create_case(f"Triage: {first}"[:120], basis,
                            f"umbra triage · {len(alerts)} alert(s), {len(unique)} indicator(s)")
    ids: dict[tuple[str, str], str] = {}
    for key, ind in unique.items():
        ent = repo.seed(case.id, EntityIn(type=ind.type, value=ind.value, confidence=0.95))
        ids[key] = ent.id
    repo.session.commit()
    cols = triage_collectors({i.type for i in unique.values()}, active=active)
    Orchestrator(repo).run(case.id, depth=0, max_entities=max(20, 4 * len(unique)),
                           collectors=cols, max_seconds=max_seconds)
    # Owned-lake hits (URLhaus / ThreatFox / Feodo) arrive as evidence rows,
    # not as `reputation_verdict`. They are the most specific listing Umbra has.
    lake_hits: dict[str, list[str]] = {}
    for ev in repo.list_evidence(case.id):
        if ev.collector == LAKE_COLLECTOR and ev.entity_id:
            name = ev.source_name.split(" (")[0].strip().lower()
            if name not in lake_hits.setdefault(ev.entity_id, []):
                lake_hits[ev.entity_id].append(name)
    props: dict[tuple[str, str], dict[str, Any]] = {}
    for key, eid in ids.items():
        ent = repo.get_entity(eid)
        if ent is not None:
            repo.session.refresh(ent)
            props[key] = dict(ent.props or {})
            if lake_hits.get(eid):
                props[key][LAKE_HITS] = lake_hits[eid]
    for key, ind in unique.items():
        if ind.type is EntityType.URL and url_in_lake(ind.value):
            props.setdefault(key, {})[LAKE_HITS] = ["urlhaus"]
    return case.id, props


def url_in_lake(url: str, settings: Any = None) -> bool:
    """Is this exact URL a URLhaus record? The precise answer for a payload on a
    shared platform, where the host's own lake hits say nothing about the host."""
    from urllib.parse import urlsplit

    from umbra.core.config import get_settings
    from umbra.lake.store import LakeStore

    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    try:
        rows = LakeStore.from_settings(settings or get_settings()).abuse_urls_for_host(host, limit=5000)
    except Exception:  # noqa: BLE001 - an unreadable lake is "unchecked", not a finding
        return False
    want = url.rstrip("/")
    return any((r.get("url") or "").rstrip("/") == want for r in rows)


def listing_of(props: dict[str, Any]) -> tuple[str, list[str]]:
    """(verdict, sources) from reputation collectors and the owned lake."""
    verdict = str(props.get("reputation_verdict") or "unknown")
    sources = ([s for s in props.get("reputation_sources") or [] if isinstance(s, str)]
               if verdict != "clean" else [])
    lake = [s for s in props.get(LAKE_HITS) or [] if isinstance(s, str)]
    if lake and props.get("platform_label"):
        # GitHub, Discord CDN and friends: strangers' uploads are listed, not
        # the platform. The reputation collector already weighed that
        # (docs/SCORING.md); the count reaches Jev as a fact. An exact URL
        # match is still a listing, via url_in_lake on the URL indicator.
        return verdict, sources
    if lake:
        return "malicious", sources + [s for s in lake if s not in sources]
    return verdict, sources


def build_facts(alert: Alert, ind: Indicator, props: dict[str, Any],
                *, asset: str | None = None) -> Facts:
    f = facts_from_props(ind.type.value, ind.value, props)
    for k in _LISTING_FACTS:
        f.trusted.pop(k, None)
    f.trusted["alert type"] = _ALERT_TYPE.get(alert.kind, alert.kind)
    for k, v in alert.context.items():
        f.trusted[k] = v
    if alert.events is not None:
        f.trusted["events in the last 24 hours"] = count_words(alert.events)
    if asset:
        f.trusted["internal host"] = asset
    for k, v in alert.untrusted.items():
        f.untrusted[k] = v
    return f


def _p_mal(answers: dict[str, Answer]) -> float:
    a = answers.get("malware_or_c2")
    return a.probability if a is not None and a.probability is not None else 0.5


def ask_jev(client: JevClient, facts: Facts) -> tuple[dict[str, Answer], bool, str]:
    """Dual ask (docs/JEV.md §4.3). Returns (answers, injection_suspected, model).

    Untrusted text can add suspicion but never remove it: if adding it lowers
    p(malware_or_c2) by more than BENIGN_SHIFT_AT, the facts-only answers are
    kept and the shift is flagged.
    """
    base = dict(SOC_TRIAGE.questions)
    facts_only = client.ask(render_state(facts.without_untrusted()), base)
    if not facts.has_untrusted:
        return dict(facts_only.answers), False, facts_only.model
    full = client.ask(render_state(facts), {**base, INJECTION_CANARY_KEY: INJECTION_CANARY})
    shift = _p_mal(facts_only.answers) - _p_mal(full.answers)
    if shift > BENIGN_SHIFT_AT:
        answers = dict(facts_only.answers)
        suspected = True
    else:
        answers = {k: v for k, v in full.answers.items() if k != INJECTION_CANARY_KEY}
        suspected = False
    answers[INJECTION_CANARY_KEY] = full.answers[INJECTION_CANARY_KEY]
    return answers, suspected, full.model


def assess(alert: Alert, props_by: dict[tuple[str, str], dict[str, Any]],
           client: JevClient | None, *, enriched: bool, asset: str | None = None,
           critical_asset: bool = False, dry_run: bool = False) -> AlertResult:
    results: list[IndicatorResult] = []
    for ind in alert.indicators:
        props = props_by.get((ind.type.value, ind.value), {})
        listing, listed_by = listing_of(props)
        facts = build_facts(alert, ind, props, asset=asset)
        state = render_state(facts)
        answers, suspected, error, model = None, False, None, None
        if client is not None and not dry_run:
            try:
                answers, suspected, model = ask_jev(client, facts)
            except JevUnavailable as exc:
                error = f"Jev unavailable: {exc}"
        dec = decide(listing, listed_by, answers, enriched=enriched,
                     critical_asset=critical_asset, injection_suspected=suspected)
        if error:
            dec.reasons.append(error)
        results.append(IndicatorResult(ind, dec, listing, listed_by, state, error, model))
    disp = worst([r.decision.disposition for r in results])
    return AlertResult(alert=alert, disposition=disp, indicators=results)
