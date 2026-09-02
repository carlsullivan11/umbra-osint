"""Label lake interface — OFAC / ransomware / curated tags.

C1 will add durable SQLite/Postgres backends and SDN parsers.
"""

from __future__ import annotations

from typing import Iterable, Protocol

from umbra.crypto.types import AddressRef, Label


class LabelStore(Protocol):
    def upsert(self, label: Label) -> None: ...

    def lookup(self, address: AddressRef) -> list[Label]: ...

    def count(self) -> int: ...


class InMemoryLabelStore:
    """Process-local store for tests and early CLI prototypes."""

    def __init__(self) -> None:
        self._by_key: dict[str, list[Label]] = {}

    def upsert(self, label: Label) -> None:
        key = label.address.key()
        bucket = self._by_key.setdefault(key, [])
        # Replace same source+tag
        bucket[:] = [
            existing
            for existing in bucket
            if not (existing.source == label.source and existing.tag == label.tag)
        ]
        bucket.append(label)

    def lookup(self, address: AddressRef) -> list[Label]:
        return list(self._by_key.get(address.key(), []))

    def count(self) -> int:
        return sum(len(v) for v in self._by_key.values())

    def extend(self, labels: Iterable[Label]) -> None:
        for label in labels:
            self.upsert(label)
