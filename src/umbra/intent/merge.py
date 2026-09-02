"""Merge deterministic + LLM intent results."""

from __future__ import annotations

from umbra.core.models import EntityType
from umbra.core.normalize import normalize_value
from umbra.intent.schema import IntentFlags, IntentSeed


def _norm_key(seed: IntentSeed) -> tuple[str, str] | None:
    try:
        nv = normalize_value(seed.type, seed.value)
        return seed.type.value, nv
    except ValueError:
        return None


def merge_flags(a: IntentFlags, b: IntentFlags) -> IntentFlags:
    """OR-merge flags — either side can turn a flag on."""
    return IntentFlags(
        want_lookalikes=a.want_lookalikes or b.want_lookalikes,
        want_breaches=a.want_breaches or b.want_breaches,
        want_corp_records=a.want_corp_records or b.want_corp_records,
        aggressive_username_probe=a.aggressive_username_probe or b.aggressive_username_probe,
        want_web_search=a.want_web_search or b.want_web_search,
        want_wayback=a.want_wayback or b.want_wayback,
    )


def merge_seeds(
    deterministic: list[IntentSeed],
    llm_seeds: list[IntentSeed],
) -> list[IntentSeed]:
    """Union by type+normalized value; keep higher confidence; prefer det notes if equal."""
    by_key: dict[tuple[str, str], IntentSeed] = {}

    def ingest(seed: IntentSeed, source: str) -> None:
        key = _norm_key(seed)
        if not key:
            return
        # rewrite value to normalized
        try:
            nv = normalize_value(seed.type, seed.value)
        except ValueError:
            return
        seed = seed.model_copy(update={"value": nv})
        props = dict(seed.props or {})
        props.setdefault("sources", [])
        if isinstance(props["sources"], list) and source not in props["sources"]:
            props["sources"] = list(props["sources"]) + [source]
        seed = seed.model_copy(update={"props": props})

        if key not in by_key:
            by_key[key] = seed
            return
        cur = by_key[key]
        # max confidence
        conf = max(cur.confidence, seed.confidence)
        include = cur.include or seed.include
        # if either says include with conf>=0.55, include
        if conf >= 0.55 and (cur.include or seed.include or conf >= 0.7):
            include = conf >= 0.55
        notes = cur.notes or seed.notes
        span = cur.source_span or seed.source_span
        props = {**(seed.props or {}), **(cur.props or {})}
        srcs = []
        for p in (cur.props or {}, seed.props or {}):
            s = p.get("sources") or []
            if isinstance(s, list):
                srcs.extend(s)
        props["sources"] = sorted(set(srcs))
        by_key[key] = IntentSeed(
            type=cur.type,
            value=cur.value,
            confidence=round(conf, 2),
            include=include,
            notes=notes,
            source_span=span,
            props=props,
        )

    for s in deterministic:
        ingest(s, "deterministic")
    for s in llm_seeds:
        ingest(s, "llm")

    seeds = list(by_key.values())
    # person low conf stay excluded unless LLM+det both strong
    for i, s in enumerate(seeds):
        if s.type == EntityType.PERSON and s.confidence < 0.75:
            seeds[i] = s.model_copy(update={"include": False})
        if s.type == EntityType.USERNAME and s.value.startswith("unknown:") and s.confidence < 0.7:
            seeds[i] = s.model_copy(update={"include": False})
        if s.confidence < 0.55:
            seeds[i] = s.model_copy(update={"include": False})

    seeds.sort(key=lambda s: (-int(s.include), -s.confidence, s.type.value, s.value))
    return seeds
