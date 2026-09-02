"""A complete, portable copy of one case as JSON.

`docs/legal/TERMS.md` promises you can export your data, and the exports that
already exist do not satisfy that: the GraphML is a graph for Gephi and the
profile is a report for a human. Neither round-trips the evidence, the runs, or
the authorization basis, so neither is a *copy of the case*.

Two things are deliberately left out:

- **`owner_id`.** It is the visitor's signed session identifier, not case data.
  Writing it into a file the visitor downloads and forwards spreads a
  credential.
- **Raw evidence bodies.** The bundle carries every evidence record and its
  content hash; the raw payloads run to tens of megabytes per case and belong in
  a separate archive if they are ever wanted.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from umbra.core.models import utcnow
from umbra.db.schema import Run

BUNDLE_VERSION = 1


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def build_bundle(repo, case_id: str) -> dict | None:
    """Every row of one case, JSON-serialisable. ``None`` if it does not exist."""
    case = repo.get_case(case_id)
    if case is None:
        return None

    runs = repo.session.query(Run).filter_by(case_id=case_id).all()
    return {
        "bundle_version": BUNDLE_VERSION,
        "exported_at": _iso(utcnow()),
        "case": {
            "id": case.id,
            "name": case.name,
            "authorization_basis": case.authorization_basis,
            "authorization_note": case.authorization_note,
            "created_at": _iso(case.created_at),
            "updated_at": _iso(case.updated_at),
            "closed": case.closed,
        },
        "entities": [
            {"id": e.id, "type": e.type, "value": e.value, "norm_key": e.norm_key,
             "display_name": e.display_name, "props": e.props,
             "confidence": e.confidence, "is_seed": e.is_seed,
             "verification": e.verification,
             "first_seen": _iso(e.first_seen), "last_seen": _iso(e.last_seen),
             "merged_into_id": e.merged_into_id}
            for e in repo.list_entities(case_id, include_merged=True)
        ],
        "edges": [
            {"id": g.id, "source_id": g.source_id, "target_id": g.target_id,
             "rel": g.rel, "confidence": getattr(g, "confidence", None),
             "props": getattr(g, "props", {})}
            for g in repo.list_edges(case_id)
        ],
        "evidence": [
            {"id": v.id, "run_id": v.run_id, "entity_id": v.entity_id,
             "collector": v.collector, "source_name": v.source_name,
             "source_url": v.source_url, "summary": v.summary,
             "confidence": v.confidence, "raw_hash": getattr(v, "raw_hash", None),
             "collected_at": _iso(getattr(v, "collected_at", None))}
            for v in repo.list_evidence(case_id)
        ],
        "runs": [
            {"id": r.id, "status": r.status, "depth": r.depth,
             "max_entities": r.max_entities, "collectors": r.collectors,
             "stats": r.stats, "started_at": _iso(getattr(r, "started_at", None)),
             "finished_at": _iso(getattr(r, "finished_at", None))}
            for r in runs
        ],
    }
