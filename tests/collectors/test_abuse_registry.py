"""Registry wiring for the abuse.ch lake collectors (P0)."""
from __future__ import annotations

from umbra.cli.main import app
from umbra.cli.playbook_cmd import _PLAYBOOK_COLLECTORS
from umbra.collectors.base import default_registry
from umbra.core.scoring import COLLECTOR_TRUST


def test_malware_infra_and_sslbl_cert_are_registered():
    names = {c.name for c in default_registry().list()}
    assert "malware_infra" in names
    assert "sslbl_cert" in names


def test_trust_weights_match_registered_collectors():
    names = {c.name for c in default_registry().list()}
    assert set(COLLECTOR_TRUST) <= names


def test_playbook_includes_abuse_collectors_in_order():
    assert "malware_infra" in _PLAYBOOK_COLLECTORS
    assert "sslbl_cert" in _PLAYBOOK_COLLECTORS
    # sslbl_cert should run after tls_cert (needs SHA-1 props from live TLS)
    assert _PLAYBOOK_COLLECTORS.index("sslbl_cert") > _PLAYBOOK_COLLECTORS.index("tls_cert")
    # malware_infra after domain_reputation (complement, not duplicate card soup)
    assert _PLAYBOOK_COLLECTORS.index("malware_infra") > _PLAYBOOK_COLLECTORS.index(
        "domain_reputation"
    )


def test_cli_exposes_abuse_sync_and_status():
    groups = {g.name: g for g in app.registered_groups}
    assert "abuse" in groups
    abuse_typer = groups["abuse"].typer_instance
    assert abuse_typer is not None
    abuse_names = {c.name for c in abuse_typer.registered_commands}
    assert "sync" in abuse_names
    assert "status" in abuse_names


def test_registry_count_is_at_least_thirty_two():
    assert len(default_registry().list()) >= 32
