"""Case retention, export and deletion.

`docs/legal/TERMS.md` §8 carried an explicit note: *"there is no self-service
deletion and no automatic case-retention limit today."* Publishing a privacy
policy that tells people to email for deletion, while offering no way to delete,
is a promise the software does not keep. This is the code that makes the
published text true.

Three judgement calls are encoded here and are what most of these tests defend:

1. **Deletion is deletion.** Rows *and* the raw evidence written to disk. A
   "deleted" case whose collector responses still sit under `data/raw/<case>/`
   has not been deleted, and that is the copy that holds the investigated
   subject's data.
2. **The audit trail survives the case, without its contents.** Every case
   carries an `authorization_basis` for accountability. Deleting the case must
   not erase the fact that it existed and was removed — but the tombstone keeps
   the id and the counts, not the subject.
3. **Automatic expiry is off by default.** A retention sweep that ships enabled
   would silently delete a self-hoster's work on upgrade. The hosted service
   sets a window; the library keeps everything until told otherwise.
"""
from __future__ import annotations

import warnings
from datetime import timedelta
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.core.models import (  # noqa: E402
    CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn, utcnow,
)
from umbra.core.normalize import entity_key  # noqa: E402
from umbra.db.repository import Repository  # noqa: E402
from umbra.db.schema import (  # noqa: E402
    AuditEvent,
    Case,
    Edge,
    Entity,
    Evidence,
    Job,
    Run,
    WatchItem,
    get_session,
    init_db,
)


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    return Repository(get_session(), settings.raw_dir)


def _populated(repo: Repository, name: str = "acme", owner: str | None = "own_1") -> str:
    """A case with one of everything that hangs off it."""
    case = repo.create_case(name, "client_engagement", owner_id=owner)
    seed = repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value=f"{name}.example",
                                       confidence=0.9))
    result = CollectorResult()
    result.entities.append(EntityIn(type=EntityType.IP, value="203.0.113.7", confidence=0.8))
    result.edges.append(EdgeIn(source_key=seed.norm_key,
                               target_key=entity_key(EntityType.IP, "203.0.113.7"),
                               rel=EdgeType.RESOLVES_TO, confidence=0.9))
    result.evidence.append(EvidenceIn(
        collector="dns_resolve", source_name="DNS", source_url="dns:",
        summary="A record", confidence=0.9, raw={"a": ["203.0.113.7"]},
        entity_key=seed.norm_key))
    repo.apply_result(case.id, None, result)
    run = repo.create_run(case.id, depth=1, max_entities=10, collectors=["dns_resolve"])
    repo.finish_run(run, "done", {"entities": 2})
    repo.enqueue_job(case.id, ["dns_resolve"], depth=1, max_entities=10)
    repo.add_watch(EntityType.DOMAIN.value, f"{name}.example",
                   case_id=case.id, label="watch")
    repo.session.commit()
    return case.id


def _raw_dir(repo: Repository, case_id: str) -> Path:
    return Path(repo.raw_dir) / case_id


# --- the delete is real ----------------------------------------------------

def test_deleting_a_case_removes_the_case(repo):
    case_id = _populated(repo)
    repo.delete_case(case_id)
    assert repo.get_case(case_id) is None


def test_deleting_a_case_removes_everything_that_hangs_off_it(repo):
    """A dangling entity row is not a privacy nicety — it is the data."""
    case_id = _populated(repo)
    repo.delete_case(case_id)
    for model in (Entity, Edge, Evidence, Run, Job, WatchItem):
        left = repo.session.query(model).filter_by(case_id=case_id).count()
        assert left == 0, f"{model.__tablename__} still holds {left} row(s)"


def test_deleting_a_case_removes_the_raw_evidence_on_disk(repo):
    """The raw collector responses are the fullest copy of what was collected.
    A DB-only delete leaves them sitting in `data/raw/<case_id>/`."""
    case_id = _populated(repo)
    assert _raw_dir(repo, case_id).exists(), "fixture did not write raw evidence"
    repo.delete_case(case_id)
    assert not _raw_dir(repo, case_id).exists()


def test_delete_reports_what_it_removed(repo):
    """An operator honoring a deletion request needs something to reply with."""
    case_id = _populated(repo)
    report = repo.delete_case(case_id)
    assert report["entities"] == 2
    assert report["edges"] == 1
    assert report["evidence"] == 1
    assert report["raw_files"] >= 1


def test_deleting_one_case_leaves_the_others_alone(repo):
    keep = _populated(repo, "keep")
    drop = _populated(repo, "drop")
    repo.delete_case(drop)
    assert repo.get_case(keep) is not None
    assert repo.session.query(Entity).filter_by(case_id=keep).count() == 2
    assert _raw_dir(repo, keep).exists()


def test_deleting_an_unknown_case_is_not_an_error(repo):
    """Delete is idempotent: a retry after a timeout must not 500."""
    assert repo.delete_case("c_nope") is None


# --- the audit trail ------------------------------------------------------

def test_the_cases_own_audit_events_go_with_it(repo):
    """They quote the case name and seed, which is the subject's data."""
    case_id = _populated(repo)
    repo.delete_case(case_id)
    assert repo.session.query(AuditEvent).filter_by(case_id=case_id).count() == 0


def test_a_tombstone_records_that_the_case_was_deleted(repo):
    """Accountability outlives the data: every case carried an
    authorization_basis, so a case vanishing without trace is its own problem."""
    case_id = _populated(repo)
    repo.delete_case(case_id, reason="user_request")
    tombs = [a for a in repo.session.query(AuditEvent).all() if a.action == "case.delete"]
    assert len(tombs) == 1
    assert tombs[0].detail["case_id"] == case_id
    assert tombs[0].detail["reason"] == "user_request"
    assert tombs[0].case_id is None, "the case row is gone; the FK cannot point at it"


def test_the_tombstone_does_not_keep_the_subject(repo):
    """Keeping the case *name* in the tombstone would defeat the deletion — the
    name is the domain, person or company that was investigated."""
    case_id = _populated(repo, "verysecret")
    repo.delete_case(case_id)
    tombs = [a for a in repo.session.query(AuditEvent).all() if a.action == "case.delete"]
    assert "verysecret" not in str(tombs[0].detail)


# --- retention sweep -------------------------------------------------------

def test_purge_is_off_by_default(repo):
    """A self-hoster who upgrades must not lose last quarter's work to a
    default they never chose."""
    from umbra.core.config import Settings

    assert Settings().case_retention_days == 0


def test_purge_removes_only_cases_past_the_window(repo):
    old = _populated(repo, "old")
    recent = _populated(repo, "recent")
    repo.backdate_case_for_stats(old, utcnow() - timedelta(days=120))
    repo.backdate_case_for_stats(recent, utcnow() - timedelta(days=10))
    removed = repo.purge_cases_older_than(90)
    assert [r["case_id"] for r in removed] == [old]
    assert repo.get_case(recent) is not None


def test_purge_with_a_zero_window_deletes_nothing(repo):
    case_id = _populated(repo)
    repo.backdate_case_for_stats(case_id, utcnow() - timedelta(days=9999))
    assert repo.purge_cases_older_than(0) == []
    assert repo.get_case(case_id) is not None


def test_purge_deletes_as_thoroughly_as_a_manual_delete(repo):
    case_id = _populated(repo)
    repo.backdate_case_for_stats(case_id, utcnow() - timedelta(days=200))
    repo.purge_cases_older_than(30)
    assert not _raw_dir(repo, case_id).exists()
    assert repo.session.query(Entity).filter_by(case_id=case_id).count() == 0


def test_purge_records_the_reason(repo):
    case_id = _populated(repo)
    repo.backdate_case_for_stats(case_id, utcnow() - timedelta(days=200))
    repo.purge_cases_older_than(30)
    tombs = [a for a in repo.session.query(AuditEvent).all() if a.action == "case.delete"]
    assert tombs[0].detail["reason"] == "retention"


def test_a_case_exactly_on_the_boundary_is_kept(repo):
    """Off-by-one here deletes a day early, and the published window becomes a
    lie in the direction that loses data."""
    case_id = _populated(repo)
    repo.backdate_case_for_stats(case_id, utcnow() - timedelta(days=90, hours=-1))
    assert repo.purge_cases_older_than(90) == []


# --- export ---------------------------------------------------------------

def test_the_export_contains_the_whole_case(repo):
    """TERMS says you can export your data. That has to mean all of it."""
    from umbra.export.bundle import build_bundle

    case_id = _populated(repo)
    bundle = build_bundle(repo, case_id)
    assert bundle["case"]["id"] == case_id
    assert len(bundle["entities"]) == 2
    assert len(bundle["edges"]) == 1
    assert len(bundle["evidence"]) == 1
    assert bundle["runs"]


def test_the_export_carries_the_authorization_basis(repo):
    """It is the field that makes a case lawful; an export without it is not a
    copy of the case."""
    from umbra.export.bundle import build_bundle

    bundle = build_bundle(repo, _populated(repo))
    assert bundle["case"]["authorization_basis"] == "client_engagement"


def test_the_export_is_json_serialisable(repo):
    """Datetimes and JSON columns both live in here; the endpoint streams it."""
    import json

    from umbra.export.bundle import build_bundle

    text = json.dumps(build_bundle(repo, _populated(repo)))
    assert "203.0.113.7" in text


def test_the_export_does_not_leak_the_owner_cookie_id(repo):
    """`owner_id` is the visitor's session identifier, not case data. Handing it
    back in a downloadable file spreads a credential."""
    from umbra.export.bundle import build_bundle

    bundle = build_bundle(repo, _populated(repo, owner="own_secret"))
    assert "own_secret" not in str(bundle)


def test_exporting_an_unknown_case_returns_nothing(repo):
    from umbra.export.bundle import build_bundle

    assert build_bundle(repo, "c_nope") is None
