from __future__ import annotations

from umbra.collectors.github_user import GithubUserCollector
from umbra.collectors.base import CollectorContext
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def test_github_supports():
    c = GithubUserCollector()
    e = Entity(
        id="1",
        case_id="c",
        type="username",
        value="github:octocat",
        norm_key=entity_key(EntityType.USERNAME, "github:octocat"),
        props={},
        confidence=1.0,
        is_seed=True,
    )
    assert c.supports(e)
