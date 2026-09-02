from __future__ import annotations

from pathlib import Path

from umbra.core.config import Settings
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.core.scoring import band_for, score_case, score_entity
from umbra.db.repository import Repository
from umbra.db.schema import Entity, init_db, get_session


def test_band_for():
    assert band_for(0.9) == "high"
    assert band_for(0.7) == "medium"
    assert band_for(0.4) == "low"
    assert band_for(0.1) == "speculative"


def test_verification_overrides():
    ent = Entity(
        id="e1",
        case_id="c",
        type="domain",
        value="x.com",
        norm_key="domain:x.com",
        props={},
        confidence=0.5,
        is_seed=False,
        verification="true",
    )
    score, bd = score_entity(
        ent,
        evidence_by_entity={},
        edges_in={},
        edges_out={},
        collectors_by_entity={},
    )
    assert score >= 0.95
    assert bd["override"] == "verification_true"

    ent.verification = "false"
    score, bd = score_entity(
        ent,
        evidence_by_entity={},
        edges_in={},
        edges_out={},
        collectors_by_entity={},
    )
    assert score <= 0.1


def test_score_case_persist(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)
    case = repo.create_case("score", "training_lab", "t")
    seed = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="example.com", confidence=0.6))
    # simulate multi-collector support
    result = CollectorResult(
        entities=[
            EntityIn(type=EntityType.IP, value="1.2.3.4", confidence=0.7),
            EntityIn(type=EntityType.DOMAIN, value="example.com", confidence=0.8),
        ],
        edges=[
            EdgeIn(
                source_key=entity_key(EntityType.DOMAIN, "example.com"),
                target_key=entity_key(EntityType.IP, "1.2.3.4"),
                rel=EdgeType.RESOLVES_TO,
                confidence=0.9,
            )
        ],
        evidence=[
            EvidenceIn(
                collector="dns_resolve",
                source_name="DNS",
                summary="A record",
                entity_key=entity_key(EntityType.DOMAIN, "example.com"),
                raw={"a": ["1.2.3.4"]},
            ),
            EvidenceIn(
                collector="tls_cert",
                source_name="TLS",
                summary="cert",
                entity_key=entity_key(EntityType.DOMAIN, "example.com"),
                raw={},
            ),
        ],
    )
    repo.apply_result(case.id, None, result)
    session.commit()

    results = score_case(repo, case.id, persist=True)
    by_key = {r.norm_key: r for r in results}
    assert "domain:example.com" in by_key
    # seed + multi collector should be fairly high
    assert by_key["domain:example.com"].new >= 0.7
    seed2 = repo.get_entity(seed.id)
    assert seed2.props.get("score_band") in {"high", "medium"}
    session.close()


def test_every_registered_collector_has_a_trust_weight():
    """A collector missing from COLLECTOR_TRUST does not fail — it silently
    scores at the 0.55 fallback, which is how three collectors ended up
    mis-weighted before anyone noticed. Adding a collector must mean deciding
    how much to trust it."""
    from umbra.collectors.base import default_registry
    from umbra.core.scoring import COLLECTOR_TRUST

    registered = {c.name for c in default_registry().list()}
    missing = registered - set(COLLECTOR_TRUST)
    assert not missing, f"collectors with no trust weight (scored at the 0.55 default): {sorted(missing)}"


def test_trust_table_has_no_entries_for_collectors_that_no_longer_exist():
    from umbra.collectors.base import default_registry
    from umbra.core.scoring import COLLECTOR_TRUST

    registered = {c.name for c in default_registry().list()}
    assert not set(COLLECTOR_TRUST) - registered
