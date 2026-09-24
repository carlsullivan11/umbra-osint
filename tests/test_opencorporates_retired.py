"""opencorporates is no longer planned by default.

It has never returned data in production: 31 evidence rows, all of them
"OpenCorporates captcha wall or block — not scraped", across the entire history
of the deployment. `A6` stopped it writing those rows as evidence — a blocked
source is a note, not a finding — but it still ran, still spent an HTTP request
and a collector slot on every org and person search, and still could not succeed.

The reason is structural rather than transient. OpenCorporates serves an
hCaptcha challenge to datacenter IPs, and the hosted deployment is a datacenter
IP. Its own description has said `prefer wikidata` since it was written.

**Removed from the default plan, not from the registry.** It works from a
residential connection, so a CLI user can still select it by name. What it must
not do is cost every hosted search a request that cannot succeed.
"""
from __future__ import annotations

from umbra.collectors.base import default_registry
from umbra.intent.plan import _ORG, _PERSON


def test_it_is_not_in_the_default_org_plan():
    assert "opencorporates" not in _ORG


def test_it_is_not_in_the_default_person_plan():
    assert "opencorporates" not in _PERSON


def test_it_is_still_registered_and_selectable():
    """It works from a residential IP. Deleting it would remove a capability
    that functions for CLI users to fix a problem only the VPS has."""
    assert default_registry().get("opencorporates") is not None


def test_wikidata_still_answers_an_org():
    """The documented substitute has to actually be in the plan."""
    assert "wikidata" in _ORG


def test_the_org_plan_is_not_empty_without_it():
    assert len(_ORG) >= 3
