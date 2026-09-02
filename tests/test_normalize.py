from __future__ import annotations

from umbra.core.normalize import entity_key, normalize_value, parent_domain
from umbra.core.models import EntityType


def test_normalize_domain():
    assert normalize_value(EntityType.DOMAIN, "https://WWW.Example.COM/path") == "example.com"


def test_entity_key_email():
    assert entity_key(EntityType.EMAIL, "A@B.com") == "email:a@b.com"


def test_parent_domain():
    assert parent_domain("a.b.example.com") == "example.com"
    assert parent_domain("example.com") is None


def test_username_normalize():
    assert normalize_value(EntityType.USERNAME, "@Foo") == "unknown:foo"
    assert normalize_value(EntityType.USERNAME, "github:Bar") == "github:bar"
