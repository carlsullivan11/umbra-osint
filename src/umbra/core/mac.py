"""MAC address normalization and the facts you can read off the address itself.

Stage S13 / M1. Everything here is pure and offline — parsing, canonicalisation
and the two flag bits IEEE defines in the first octet. Vendor resolution is a
separate concern (`umbra.lake.oui`), because it needs data and this does not.

The reason the flags matter as much as the vendor: a locally administered
address has **no registrant by construction**. Modern phones rotate a private
Wi-Fi address per network, so resolving one to a manufacturer is fiction, and
treating it as a durable device ID is worse than useless in an investigation.
"""
from __future__ import annotations

import re

# Separated forms only. A bare 12-hex-digit run is a shape shared with commit
# SHAs, hashes and build ids; matching it unanchored turns ordinary text into
# MAC seeds, so callers that really have a bare address pass it explicitly.
_SEPARATED_RE = re.compile(
    r"(?<![0-9A-Fa-f])("
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"      # aa:bb:cc:dd:ee:ff
    r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"     # aa-bb-cc-dd-ee-ff
    r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"    # aabb.ccdd.eeff (Cisco)
    r")(?![0-9A-Fa-f])"
)

# Hex-only lengths we accept: a full 48-bit address, or a 24-bit OUI prefix
# ("what is this vendor?" is a real question). MA-M (28) and MA-S (36) block
# boundaries fall mid-octet and are not something operators type.
_FULL_HEX = 12
_PREFIX_HEX = 6


def normalize_mac(value: str) -> str:
    """Strip separators and upper-case: 'a4:83:e7:…' -> 'A483E7…'.

    Mirrors `import_oui.normalize_mac()` in umbra-wiki so the app and the data
    pipeline agree on what a prefix is.
    """
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()


def canonical_mac(value: str) -> str:
    """Canonical form: colon-separated, upper-case. Raises on anything else."""
    hexs = normalize_mac(value)
    if len(hexs) not in (_FULL_HEX, _PREFIX_HEX):
        raise ValueError(f"invalid MAC address: {value!r}")
    return ":".join(hexs[i:i + 2] for i in range(0, len(hexs), 2))


def is_mac_like(value: str) -> bool:
    try:
        canonical_mac(value)
    except ValueError:
        return False
    return bool(value) and len(normalize_mac(value)) in (_FULL_HEX, _PREFIX_HEX)


def find_macs(text: str) -> list[str]:
    """Canonical MACs appearing in free text, in order, de-duplicated."""
    out: list[str] = []
    for m in _SEPARATED_RE.finditer(text or ""):
        try:
            c = canonical_mac(m.group(1))
        except ValueError:
            continue
        if c not in out:
            out.append(c)
    return out


def mac_facts(value: str) -> dict:
    """What the address says about itself — no lookups, no network.

    Returns the canonical form, the OUI, the two IEEE flag bits, and notes an
    investigator needs to see next to any vendor claim.
    """
    canon = canonical_mac(value)
    hexs = normalize_mac(canon)
    first = int(hexs[0:2], 16)

    is_prefix = len(hexs) == _PREFIX_HEX
    is_multicast = bool(first & 0b1)          # I/G bit — the low bit
    is_local = bool(first & 0b10)             # U/L bit
    is_broadcast = hexs == "F" * 12

    # A universally administered address is registered to whoever holds the
    # block. A locally administered one is not, so "randomized" is the useful
    # reading for a unicast address with the local bit set — that is exactly
    # what iOS/Android private Wi-Fi addresses look like.
    is_probably_randomized = is_local and not is_multicast

    notes: list[str] = []
    if is_broadcast:
        notes.append("Broadcast address (FF:FF:FF:FF:FF:FF) — not a device identity.")
    elif is_multicast:
        notes.append(
            "Multicast/group address (I/G bit set) — a destination, not a station's "
            "burned-in address."
        )
    if is_probably_randomized:
        notes.append(
            "Locally administered (U/L bit set) — probably a randomized or "
            "software-assigned address. It has no IEEE registrant, and it is "
            "**not** a durable hardware identifier: phones rotate these per "
            "network."
        )

    return {
        "mac": canon,
        "oui": ":".join(hexs[i:i + 2] for i in range(0, min(6, len(hexs)), 2)),
        "is_prefix": is_prefix,
        "is_multicast": is_multicast,
        "is_local": is_local,
        "is_broadcast": is_broadcast,
        "is_probably_randomized": is_probably_randomized,
        "notes": notes,
    }
