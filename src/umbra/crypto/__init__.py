"""Crypto address screening & bounded flow framework (design C0).

Import-stable surface for upcoming collectors. No network I/O at import time.
See docs/CRYPTO-EXPLORATION.md.
"""

from __future__ import annotations

from umbra.crypto.labels import InMemoryLabelStore, LabelStore
from umbra.crypto.normalize import NormalizedAddress, detect_and_normalize
from umbra.crypto.services import ServiceRegistry
from umbra.crypto.types import (
    AddressRef,
    Label,
    LabelTag,
    ServiceDef,
    ServiceKind,
    Transfer,
)

__all__ = [
    "AddressRef",
    "InMemoryLabelStore",
    "Label",
    "LabelStore",
    "LabelTag",
    "NormalizedAddress",
    "ServiceDef",
    "ServiceKind",
    "ServiceRegistry",
    "Transfer",
    "detect_and_normalize",
]
