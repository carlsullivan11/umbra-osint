from __future__ import annotations

from pathlib import Path

from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.repository import Repository
from umbra.db.schema import init_db, get_session
from umbra.core.config import Settings


def test_upsert_and_edges(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)
    case = repo.create_case("t", "training_lab", "unit test")
    e1 = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="Example.COM"))
    assert e1.norm_key == "domain:example.com"
    # second seed same key merges
    e2 = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="example.com", props={"x": 1}))
    assert e2.id == e1.id
    assert e2.props.get("x") == 1

    result = CollectorResult(
        entities=[EntityIn(type=EntityType.IP, value="1.2.3.4")],
        edges=[
            EdgeIn(
                source_key=entity_key(EntityType.DOMAIN, "example.com"),
                target_key=entity_key(EntityType.IP, "1.2.3.4"),
                rel=EdgeType.RESOLVES_TO,
            )
        ],
        evidence=[
            EvidenceIn(
                collector="test",
                source_name="unit",
                summary="hi",
                raw={"ok": True},
                entity_key=entity_key(EntityType.DOMAIN, "example.com"),
            )
        ],
    )
    stats = repo.apply_result(case.id, None, result)
    session.commit()
    assert stats["entities"] >= 1
    ents = repo.list_entities(case.id)
    assert any(e.type == "ip" and e.value == "1.2.3.4" for e in ents)
    assert len(repo.list_edges(case.id)) == 1
    assert len(repo.list_evidence(case.id)) == 1
    session.close()
