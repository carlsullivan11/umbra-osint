from __future__ import annotations

from umbra.collectors.email_split import EmailSplitCollector
from umbra.collectors.base import CollectorContext
from umbra.core.config import Settings
from umbra.db.schema import Entity
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key


class DummyHttp:
    pass


def test_email_split():
    col = EmailSplitCollector()
    ent = Entity(
        id="e1",
        case_id="c1",
        type=EntityType.EMAIL.value,
        value="alice@example.com",
        norm_key=entity_key(EntityType.EMAIL, "alice@example.com"),
        props={},
        confidence=1.0,
        is_seed=True,
    )
    ctx = CollectorContext(settings=Settings(), case_id="c1", run_id="r1", http=DummyHttp())  # type: ignore[arg-type]
    result = col.collect(ent, ctx)
    assert any(e.type == EntityType.DOMAIN and e.value == "example.com" for e in result.entities)
    assert any(e.type == EntityType.USERNAME for e in result.entities)
    assert result.evidence
