"""Typed records for crypto screening / hop expansion (no DB coupling yet)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LabelTag(str, Enum):
    """v1 label taxonomy — keep in sync with docs/CRYPTO-EXPLORATION.md."""

    SANCTIONED_OFAC = "sanctioned_ofac"
    RANSOMWARE_PAYMENT = "ransomware_payment"
    THEFT_PROCEEDS = "theft_proceeds"
    MIXER_SERVICE = "mixer_service"
    MIXER_USER_INTERACTION = "mixer_user_interaction"
    BRIDGE = "bridge"
    EXCHANGE_DEPOSIT = "exchange_deposit"
    SCAM_REPORTED = "scam_reported"


class ServiceKind(str, Enum):
    MIXER = "mixer"
    BRIDGE = "bridge"
    EXCHANGE = "exchange"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class AddressRef:
    """Canonical chain + address pair."""

    chain: str  # btc | eth | tron | sol | bsc | ltc | xrp | other
    address: str

    def key(self) -> str:
        return f"{self.chain}:{self.address}"


@dataclass(frozen=True, slots=True)
class Transfer:
    chain: str
    txid: str
    from_addr: str
    to_addr: str
    asset: str  # native symbol or token contract / asset id
    amount_raw: int
    decimals: int = 0
    index: int = 0
    block_time: datetime | None = None
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Label:
    address: AddressRef
    tag: LabelTag
    source: str
    confidence: float
    url: str | None = None
    summary: str = ""
    observed_at: datetime | None = None
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ServiceDef:
    name: str
    kind: ServiceKind
    chain: str
    # Contract or deposit addresses associated with the service
    addresses: tuple[str, ...]
    tags: tuple[str, ...] = ()
    notes: str = ""
    url: str | None = None
