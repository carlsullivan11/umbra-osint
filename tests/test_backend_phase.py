from __future__ import annotations

from pathlib import Path

from umbra.collectors.lookalike_domains import generate_lookalikes
from umbra.core.monitor import diff_snapshots
from umbra.core.models import EntityIn, EntityType
from umbra.core.config import Settings
from umbra.db.repository import Repository
from umbra.db.schema import init_db, get_session


def test_lookalike_generates():
    variants = generate_lookalikes("example.com", limit=40)
    assert variants
    assert any(v.endswith(".net") for v, _ in variants)
    assert any(t == "transpose" for _, t in variants)


def test_diff_snapshots():
    d = diff_snapshots({"a": ["1.1.1.1"]}, {"a": ["1.1.1.1", "8.8.8.8"]})
    assert d["changed"] is True
    assert d["changes"]


def test_verify_and_merge(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)
    case = repo.create_case("m", "training_lab", "t")
    a = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="a.example.com"))
    b = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="b.example.com"))
    repo.set_verification(a.id, "true", "confirmed")
    assert repo.get_entity(a.id).verification == "true"
    keep = repo.merge_entities(case.id, a.id, b.id)
    assert keep.id == a.id
    dropped = repo.get_entity(b.id)
    assert dropped.merged_into_id == a.id
    active = repo.list_entities(case.id)
    assert all(e.id != b.id for e in active)
    session.close()
