"""phone_validate collector — offline libphonenumber only."""
from __future__ import annotations

from pathlib import Path

import httpx

from umbra.collectors.base import CollectorContext
from umbra.collectors.phone_validate import PhoneValidateCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _entity(value: str) -> Entity:
    e = Entity(
        id="e1",
        case_id="c1",
        type=EntityType.PHONE.value,
        value=value,
        norm_key=entity_key(EntityType.PHONE, value),
        confidence=0.9,
        is_seed=True,
        props={},
    )
    return e


def test_phone_validate_sets_props_and_evidence(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    ctx = CollectorContext(
        settings=settings,
        case_id="c1",
        run_id="r1",
        http=httpx.Client(),
    )
    try:
        col = PhoneValidateCollector()
        res = col.collect(_entity("+14155552671"), ctx)
    finally:
        ctx.http.close()

    assert res.entities
    props = res.entities[0].props or {}
    assert props.get("phone_e164") == "+14155552671"
    assert props.get("phone_possible") is True
    assert props.get("reputation_verdict") in {"valid", "possible"}
    assert any(ev.collector == "phone_validate" for ev in res.evidence)
    assert any("numbering-plan" in n.lower() or "offline" in n.lower() for n in res.notes)
