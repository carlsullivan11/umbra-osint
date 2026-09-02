"""Provider protocol for capped transfer fetch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from umbra.crypto.types import AddressRef, Transfer


@dataclass(frozen=True, slots=True)
class ProviderCaps:
    max_transfers: int = 200
    max_pages: int = 5


class ChainProvider(Protocol):
    chain: str

    def get_transfers(
        self,
        address: AddressRef,
        *,
        caps: ProviderCaps | None = None,
    ) -> list[Transfer]:
        """Return newest-first transfers, already capped."""
        ...
