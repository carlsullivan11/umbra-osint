"""Telling somebody when a watched address moves (C6).

The index has been quietly recording for a while and waking nobody. C6 wires it
to the ops-event path that already reaches Telegram and `/ops/events`.

**The watch set and the alert set are deliberately different**, and that is the
whole design. C3 put the Tornado pools into the watch set so deposits are
*recorded* as they happen — but pools receive deposits constantly, and alerting
on each one would produce exactly the muted channel the ops digest was fixed to
avoid. A stranger using a mixer is Tuesday.

What is worth waking someone for is a **labelled** address moving: one of the
961 OFAC entries sending or receiving. That is rare, and it is the event an
investigator actually wants pushed rather than polled.

The severity split follows the same logic — a sanctioned address moving funds
*into a mixer* is the strongest signal available here, and it earns the higher
level.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.crypto import alerts  # noqa: E402
from umbra.crypto import lake as crypto_lake  # noqa: E402
from umbra.crypto.types import AddressRef, Label, LabelTag  # noqa: E402
from umbra.db.repository import Repository  # noqa: E402
from umbra.db.schema import OpsEvent, get_session, init_db  # noqa: E402
from umbra.lake.store import LakeStore  # noqa: E402

SANCTIONED = "0x7f367cc41522ce07553e823bf3be79a889debe1b"
STRANGER = "0x1111111111111111111111111111111111111111"
TORNADO = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"


@pytest.fixture
def env(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    repo = Repository(get_session(), settings.raw_dir)
    store = LakeStore(f"sqlite:///{tmp_path / 'lake.db'}")
    crypto_lake.replace_source(store, "ofac_sdn", [Label(
        address=AddressRef(chain="eth", address=SANCTIONED),
        tag=LabelTag.SANCTIONED_OFAC, source="ofac_sdn", confidence=0.98,
        summary="OFAC SDN listing: TEST ENTITY")])
    return repo, store


def _transfer(frm=STRANGER, to=SANCTIONED, txid="0xtx1", asset="USDT",
              amount=1_000_000, decimals=6):
    return {"chain": "eth", "txid": txid, "log_index": 0, "from_addr": frm,
            "to_addr": to, "asset": asset, "contract": "0xdac1",
            "amount_raw": str(amount), "decimals": decimals,
            "block_number": 100}


def _events(repo):
    return repo.session.query(OpsEvent).all()


# --- what is worth waking someone for -------------------------------------

def test_a_labelled_address_moving_raises_an_alert(env):
    repo, store = env
    assert alerts.raise_for_transfers(repo, store, [_transfer()]) == 1
    assert len(_events(repo)) == 1


def test_the_alert_names_the_address_and_the_label(env):
    """An alert an investigator cannot act on without opening a database is not
    much of an alert."""
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer()])
    event = _events(repo)[0]
    assert SANCTIONED[:12] in event.title or SANCTIONED in str(event.detail)
    assert "sanctioned_ofac" in str(event.detail)
    assert "TEST ENTITY" in str(event.detail)


def test_the_amount_and_asset_are_carried(env):
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer(amount=2_500_000)])
    detail = str(_events(repo)[0].detail)
    assert "USDT" in detail
    assert "2.5" in detail


def test_direction_is_recorded(env):
    """"Sent 500k" and "received 500k" are different findings."""
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer(frm=SANCTIONED, to=STRANGER)])
    assert "sent" in str(_events(repo)[0].detail).lower()


# --- what is not ----------------------------------------------------------

def test_a_stranger_using_a_mixer_does_not_alert(env):
    """Pools receive deposits constantly. Alerting on each would produce the
    muted channel the ops digest exists to prevent."""
    repo, store = env
    assert alerts.raise_for_transfers(
        repo, store, [_transfer(frm=STRANGER, to=TORNADO)]) == 0
    assert _events(repo) == []


def test_two_unwatched_parties_do_not_alert(env):
    repo, store = env
    assert alerts.raise_for_transfers(
        repo, store, [_transfer(frm=STRANGER, to="0x2222222222222222222222222222222222222222")]) == 0


def test_a_delisted_label_stops_alerting(env):
    """Alerting on an address because it *used* to be sanctioned is surveillance
    without a reason."""
    repo, store = env
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    assert alerts.raise_for_transfers(repo, store, [_transfer()]) == 0


# --- severity -------------------------------------------------------------

def test_a_sanctioned_address_touching_a_mixer_is_the_loudest(env):
    """The strongest signal this module can produce."""
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer(frm=SANCTIONED, to=TORNADO)])
    event = _events(repo)[0]
    assert event.severity in {"S1", "S2"}
    assert "mixer" in str(event.detail).lower()


def test_an_ordinary_labelled_movement_is_quieter(env):
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer()])
    mixer_free = _events(repo)[0]
    assert mixer_free.severity not in {"S1"}


# --- it must not become noise ---------------------------------------------

def test_the_same_transfer_alerts_once(env):
    """The tail re-reads overlapping windows; a replayed transfer is not news."""
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer()])
    alerts.raise_for_transfers(repo, store, [_transfer()])
    assert len(_events(repo)) == 1


def test_distinct_transfers_are_distinct_alerts(env):
    """Fingerprinting on the address alone would collapse a week of movement
    into one row that nobody looks at twice."""
    repo, store = env
    alerts.raise_for_transfers(repo, store, [_transfer(txid="0xa"),
                                             _transfer(txid="0xb")])
    assert len(_events(repo)) == 2


def test_a_burst_is_capped(env):
    """A hot address could produce hundreds of transfers in one tick. Paging
    someone three hundred times is the same as not paging them."""
    repo, store = env
    many = [_transfer(txid=f"0x{i}") for i in range(200)]
    raised = alerts.raise_for_transfers(repo, store, many)
    assert raised <= alerts.MAX_ALERTS_PER_TICK
    assert len(_events(repo)) <= alerts.MAX_ALERTS_PER_TICK + 1


def test_the_cap_says_how_much_it_swallowed(env):
    """A silent cap reads as "that was all of it"."""
    repo, store = env
    many = [_transfer(txid=f"0x{i}") for i in range(200)]
    alerts.raise_for_transfers(repo, store, many)
    titles = " ".join(e.title for e in _events(repo))
    assert "more" in titles.lower() or "200" in titles


def test_nothing_to_alert_on_is_silent(env):
    repo, store = env
    assert alerts.raise_for_transfers(repo, store, []) == 0
    assert _events(repo) == []
