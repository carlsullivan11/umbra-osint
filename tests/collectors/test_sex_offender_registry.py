"""sex_offender_registry collector wiring."""

from types import SimpleNamespace

from umbra.collectors.base import CollectorContext
from umbra.collectors.sex_offender_registry import SexOffenderRegistryCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType


def test_sor_skips_single_token_name():
    c = SexOffenderRegistryCollector()
    ent = SimpleNamespace(type=EntityType.PERSON.value, value="Madonna", display_name="Madonna", props={})
    result = c.collect(
        ent,  # type: ignore[arg-type]
        CollectorContext(settings=Settings(), case_id="c", run_id="r", http=SimpleNamespace()),
    )
    assert result.entities == []
    assert any("first and last" in n for n in result.notes)
