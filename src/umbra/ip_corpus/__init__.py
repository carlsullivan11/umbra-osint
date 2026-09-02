"""Passive IP enrichment for graph entities already in Umbra (Phase A).

Not a full-Internet scan. Only public ``EntityType.IP`` rows that lack
geo/ASN markers get the sentinel-style passive collector set, **in place**
on their existing cases.
"""
from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from umbra.collectors.base import CollectorContext, default_registry
from umbra.core.config import Settings, get_settings
from umbra.core.http_guard import GuardedClient
from umbra.core.models import utcnow
from umbra.db.repository import Repository
from umbra.db.schema import Entity

logger = logging.getLogger("umbra.ip_corpus")

# Same allowlist as sentinel — never http_probe / active surface.
PASSIVE_COLLECTORS = [
    "rdap_ip",
    "asn_cymru",
    "ip_geo",
    "ip_reputation",
    "malware_infra",
]

ACTIVE_FORBIDDEN = frozenset({
    "http_probe",
    "tech_fingerprint",
    "html_links",
    "tls_cert",
    "sslbl_cert",
})

# Markers that mean "already had a useful passive pass"
_ENRICHED_KEYS = frozenset({
    "geo_country",
    "geo_city",
    "asn",
    "as_number",
    "asn_name",
    "rdap_name",
    "rdap_country",
    "cymru_asn",
    "cymru",  # asn_cymru writes parsed origin rows under this key
    "passive_enriched_at",
})

DEFAULT_COOLDOWN_DAYS = 7


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_reserved or ip.is_unspecified:
        return False
    # CGNAT / shared
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def _parse_ts(raw: Any) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def is_enriched(props: dict | None, *, cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
                now: datetime | None = None) -> bool:
    """True if this entity already has passive markers / recent stamp."""
    p = props or {}
    now = now or utcnow()
    stamp = _parse_ts(p.get("passive_enriched_at"))
    if stamp is not None:
        if now - stamp < timedelta(days=cooldown_days):
            return True
        # stale stamp alone is not enough if we have other markers
    for k in _ENRICHED_KEYS:
        if k == "passive_enriched_at":
            continue
        if p.get(k) not in (None, "", [], {}):
            return True
    return False


def list_ips_needing_enrichment(
    session: Session,
    *,
    cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
    limit: int | None = None,
) -> list[Entity]:
    """All unmerged public IP entities missing enrichment (newest first)."""
    q = (
        select(Entity)
        .where(
            Entity.type == "ip",
            Entity.merged_into_id.is_(None),
            Entity.value.is_not(None),
        )
        .order_by(Entity.last_seen.desc())
    )
    rows = list(session.scalars(q).all())
    out: list[Entity] = []
    seen_vals: set[str] = set()
    for ent in rows:
        val = (ent.value or "").strip()
        if not val or not is_public_ip(val):
            continue
        # one row per distinct IP for batching (prefer newest)
        key = val.lower() if ":" in val else val
        if key in seen_vals:
            continue
        if is_enriched(ent.props, cooldown_days=cooldown_days):
            continue
        seen_vals.add(key)
        out.append(ent)
        if limit is not None and len(out) >= limit:
            break
    return out


def coverage_stats(session: Session) -> dict[str, int]:
    rows = list(
        session.scalars(
            select(Entity).where(
                Entity.type == "ip",
                Entity.merged_into_id.is_(None),
            )
        ).all()
    )
    public = [e for e in rows if is_public_ip(e.value or "")]
    with_geo = sum(1 for e in public if (e.props or {}).get("geo_country"))
    with_asn = sum(1 for e in public if _has_asn_signal(e.props))
    enriched = sum(1 for e in public if is_enriched(e.props))
    return {
        "ip_entities": len(rows),
        "public_ips": len(public),
        "with_geo": with_geo,
        "with_asn": with_asn,
        "enriched": enriched,
        "needing": sum(1 for e in public if not is_enriched(e.props)),
    }


def _has_asn_signal(props: dict | None) -> bool:
    p = props or {}
    if p.get("asn") or p.get("as_number") or p.get("cymru_asn"):
        return True
    cymru = p.get("cymru")
    if isinstance(cymru, list) and cymru:
        return True
    if isinstance(cymru, dict) and cymru:
        return True
    return False


def list_case_ips_needing_enrichment(
    session: Session,
    case_id: str,
    *,
    cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
    limit: int | None = 80,
) -> list[Entity]:
    """Public IP entities on one case that still need a passive pass."""
    q = (
        select(Entity)
        .where(
            Entity.case_id == case_id,
            Entity.type == "ip",
            Entity.merged_into_id.is_(None),
            Entity.value.is_not(None),
        )
        .order_by(Entity.last_seen.desc())
    )
    out: list[Entity] = []
    for ent in session.scalars(q).all():
        if not is_public_ip(ent.value or ""):
            continue
        if is_enriched(ent.props, cooldown_days=cooldown_days):
            continue
        out.append(ent)
        if limit is not None and len(out) >= limit:
            break
    return out


def ensure_case_ips_enriched(
    repo: Repository,
    case_id: str,
    *,
    settings: Settings | None = None,
    limit: int = 80,
) -> dict[str, Any]:
    """Phase B safety net: enrich public IPs on a case after a normal run."""
    needing = list_case_ips_needing_enrichment(
        repo.session, case_id, limit=limit
    )
    if not needing:
        return {"ips": 0, "collector_runs": 0, "cases": 0}
    return enrich_entities(repo, needing, settings=settings)


def graph_has_ip(session: Session, ip: str) -> bool:
    """True if any unmerged IP entity already holds this address."""
    val = (ip or "").strip()
    if not val:
        return False
    row = session.scalars(
        select(Entity.id).where(
            Entity.type == "ip",
            Entity.merged_into_id.is_(None),
            Entity.value == val,
        ).limit(1)
    ).first()
    return row is not None


def intake_abuse_lake_ips(
    repo: Repository,
    *,
    limit: int = 40,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Seed distinct public IPs from the owned abuse.ch lake into a corpus case.

    Only addresses not already present as graph IP entities. Passive case uses
    ``public_cti`` — the lake is published threat intel Umbra already mirrors.
    """
    from umbra.core.models import EntityIn, EntityType
    from umbra.lake.store import LakeStore

    settings = settings or get_settings()
    store = LakeStore.from_settings(settings)
    hosts = store.abuse_distinct_ip_hosts(limit=limit * 4)

    new_ips: list[str] = []
    for h in hosts:
        if not is_public_ip(h):
            continue
        if graph_has_ip(repo.session, h):
            continue
        new_ips.append(h)
        if len(new_ips) >= limit:
            break

    if not new_ips:
        return {"seeded": 0, "case_id": None, "enriched_ips": 0}

    case = repo.create_case(
        f"Corpus: abuse.ch lake IPs ({len(new_ips)})",
        "public_cti",
        "Phase B intake — public IPs from the owned abuse.ch lake "
        "(URLhaus/ThreatFox/Feodo hosts). Passive enrichment only.",
    )
    for ip in new_ips:
        try:
            repo.seed(
                case.id,
                EntityIn(
                    type=EntityType.IP,
                    value=ip,
                    confidence=0.85,
                    props={"source": "abusech_lake", "corpus": "phase_b"},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("skip seed %s: %s", ip, exc)
    repo.session.commit()

    ents = list_case_ips_needing_enrichment(repo.session, case.id, limit=limit)
    stats = enrich_entities(repo, ents, settings=settings) if ents else {
        "ips": 0, "collector_runs": 0
    }
    return {
        "seeded": len(new_ips),
        "case_id": case.id,
        "enriched_ips": stats.get("ips", 0),
        "collector_runs": stats.get("collector_runs", 0),
    }


def assert_passive_only(names: Iterable[str]) -> list[str]:
    cols = [n.strip() for n in names if n and n.strip()]
    bad = [n for n in cols if n in ACTIVE_FORBIDDEN]
    if bad:
        raise ValueError(f"active collectors forbidden in IP backfill: {bad}")
    unknown_active = [n for n in cols if n.startswith("http") or n in ACTIVE_FORBIDDEN]
    if unknown_active:
        raise ValueError(f"refusing collectors: {unknown_active}")
    return cols


def _stamp(ent: Entity) -> None:
    props = dict(ent.props or {})
    props["passive_enriched_at"] = utcnow().isoformat()
    props["passive_enrichment"] = "ip_corpus_backfill"
    ent.props = props


def enrich_entities(
    repo: Repository,
    entities: list[Entity],
    *,
    collectors: list[str] | None = None,
    settings: Settings | None = None,
    stamp: bool = True,
) -> dict[str, Any]:
    """Run passive collectors on the given IP entities (grouped by case)."""
    settings = settings or get_settings()
    names = assert_passive_only(collectors or PASSIVE_COLLECTORS)
    registry = default_registry()
    cols = registry.resolve_many(names)
    if not cols:
        raise ValueError("no collectors resolved")

    by_case: dict[str, list[Entity]] = {}
    for e in entities:
        by_case.setdefault(e.case_id, []).append(e)

    stats: dict[str, Any] = {
        "cases": 0,
        "ips": 0,
        "collector_runs": 0,
        "errors": 0,
        "notes": [],
        "run_ids": [],
    }
    timeout = float(getattr(settings, "collector_timeout_s", 0) or 0)
    headers = {"User-Agent": settings.user_agent}

    with GuardedClient(headers=headers, timeout=settings.request_timeout_s) as http:
        for case_id, ents in by_case.items():
            case = repo.get_case(case_id)
            if not case:
                stats["notes"].append(f"skip unknown case {case_id}")
                continue
            run = repo.create_run(
                case_id,
                depth=0,
                max_entities=max(40, len(ents) * 5),
                collectors=[c.name for c in cols],
            )
            stats["run_ids"].append(run.id)
            stats["cases"] += 1
            ctx_base = {
                "settings": settings,
                "case_id": case_id,
                "run_id": run.id,
                "http": http,
            }
            for ent in ents:
                stats["ips"] += 1
                # refresh
                fresh = repo.session.get(Entity, ent.id)
                if not fresh or fresh.merged_into_id:
                    continue
                for col in cols:
                    if not col.supports(fresh):
                        continue
                    ctx = CollectorContext(**ctx_base)
                    try:
                        if timeout and timeout > 0:
                            pool = ThreadPoolExecutor(max_workers=1)
                            try:
                                result = pool.submit(col.collect, fresh, ctx).result(
                                    timeout=timeout
                                )
                            finally:
                                pool.shutdown(wait=False, cancel_futures=True)
                        else:
                            result = col.collect(fresh, ctx)
                    except FuturesTimeout:
                        stats["errors"] += 1
                        stats["notes"].append(
                            f"{col.name} on {fresh.value}: timeout"
                        )
                        continue
                    except Exception as exc:  # noqa: BLE001
                        stats["errors"] += 1
                        stats["notes"].append(f"{col.name} on {fresh.value}: {exc}")
                        continue
                    stats["collector_runs"] += 1
                    repo.apply_result(case_id, run.id, result)
                    repo.session.commit()
                    if result.notes:
                        stats["notes"].extend(result.notes[:3])
                    fresh = repo.session.get(Entity, ent.id) or fresh
                if stamp and fresh:
                    _stamp(fresh)
                    repo.session.commit()
            try:
                from umbra.core.scoring import score_case

                score_case(repo, case_id, persist=True)
            except Exception as exc:  # noqa: BLE001
                stats["notes"].append(f"scoring {case_id}: {exc}")
            repo.finish_run(run, "ok", {
                "ips": len(ents),
                "collector_runs": stats["collector_runs"],
                "source": "ip_corpus_backfill",
            })
            repo.session.commit()

    return stats
