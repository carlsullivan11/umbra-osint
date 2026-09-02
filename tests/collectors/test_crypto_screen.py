"""crypto_screen collector — offline OFAC lake, no DDG."""

from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from umbra.collectors.crypto_screen import CryptoScreenCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType


def test_crypto_screen_unrecognised():
    col = CryptoScreenCollector()
    ctx = SimpleNamespace(settings=Settings(data_dir=Path("/tmp/umbra-crypto-test-none")))
    entity = SimpleNamespace(value="not-an-address", type=EntityType.CRYPTO_ADDRESS.value, norm_key="crypto_address:x")
    res = col.collect(entity, ctx)
    assert res.notes
    assert not res.entities


def test_crypto_screen_empty_lake_is_unchecked(tmp_path: Path):
    col = CryptoScreenCollector()
    settings = Settings(data_dir=tmp_path)
    ctx = SimpleNamespace(settings=settings)
    addr = "0x" + ("11" * 20)
    entity = SimpleNamespace(
        value=f"eth:{addr}",
        type=EntityType.CRYPTO_ADDRESS.value,
        norm_key=f"crypto_address:eth:{addr}",
    )
    res = col.collect(entity, ctx)
    assert res.entities
    props = res.entities[0].props
    assert props["crypto_checked"] is False
    assert "not clean" in " ".join(res.notes).lower() or "empty" in " ".join(res.notes).lower()
