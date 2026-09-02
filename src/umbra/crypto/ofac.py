"""OFAC SDN — sanctioned digital currency addresses.

The primary label source for C1: official, free, no key. The live file carries
977 digital currency addresses across 13 assets, attached to 94 sanctioned
entities.

Two properties shape everything here, and both are about not asserting more than
the list does.

**A listing is a claim about a point in time.** OFAC removes entries — Tornado
Cash was designated in 2022 and delisted in 2025 — and an address Umbra still
labels `sanctioned_ofac` after removal is a false accusation with legal weight
behind it. `umbra.crypto.lake` therefore treats a sync as a full-file
reconciliation rather than an append.

**The list sanctions people, not strings.** Every label carries the SDN entity,
its uid and its programmes, so the claim can be checked against the same public
file anyone can download. "This address is bad" is not a finding; "belongs to
SDN uid 25308, Xiaobing YAN, programme SDNTK" is.

The asset code is not the chain. OFAC writes `Digital Currency Address - USDT`,
and that address may be ERC-20 or TRC-20 — the chain comes from the address
format, and the OFAC code is kept as provenance.
"""
from __future__ import annotations

import logging
import re
from typing import Iterator
from xml.etree import ElementTree

from umbra.crypto.normalize import detect_and_normalize
from umbra.crypto.types import AddressRef, Label, LabelTag

logger = logging.getLogger(__name__)

# Redirects to a presigned S3 URL, so callers must follow redirects.
SDN_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
SOURCE = "ofac_sdn"
PUBLIC_URL = "https://sanctionslist.ofac.treas.gov/Home/SdnList"

_ID_TYPE_RE = re.compile(r"^Digital Currency Address - ([A-Z0-9]+)$")

# Only used when the address format is unrecognisable — Monero and Zcash do not
# match the EVM/BTC/TRON patterns, and dropping them would silently lose
# sanctioned addresses. Format detection wins whenever it succeeds.
_ASSET_FALLBACK_CHAIN = {
    "XBT": "btc", "BCH": "bch", "LTC": "ltc", "XMR": "xmr", "ZEC": "zec",
    "DASH": "dash", "DOGE": "doge", "ETH": "eth", "ETC": "etc", "TRX": "tron",
    "SOL": "sol", "XVG": "xvg", "ARB": "eth", "BSC": "bsc", "XRP": "xrp",
}

# The government publishing it is the reason this outranks a crowdsourced tag.
CONFIDENCE = 0.98


def _text(element, tag: str) -> str:
    """Namespace-agnostic child text — the SDN file declares a default ns."""
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == tag and (child.text or "").strip():
            return child.text.strip()
    return ""


def _entries(xml: str) -> Iterator[ElementTree.Element]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        logger.warning("SDN parse failed: %s", exc)
        return
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "sdnEntry":
            yield element


def _entity_name(entry: ElementTree.Element) -> str:
    first = _text(entry, "firstName")
    last = _text(entry, "lastName")
    return " ".join(part for part in (first, last) if part).strip()


def _programs(entry: ElementTree.Element) -> list[str]:
    out: list[str] = []
    for child in entry.iter():
        if child.tag.rsplit("}", 1)[-1] == "program" and (child.text or "").strip():
            out.append(child.text.strip())
    return out


def parse(xml: str) -> list[Label]:
    """Sanctioned addresses from one SDN.XML. Never raises on bad input."""
    if not xml or not xml.strip():
        return []

    labels: list[Label] = []
    for entry in _entries(xml):
        uid = _text(entry, "uid")
        name = _entity_name(entry)
        programs = _programs(entry)
        sdn_type = _text(entry, "sdnType")

        for id_el in entry.iter():
            if id_el.tag.rsplit("}", 1)[-1] != "id":
                continue
            id_type = ""
            id_number = ""
            for child in id_el:
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "idType":
                    id_type = (child.text or "").strip()
                elif tag == "idNumber":
                    id_number = (child.text or "").strip()
            match = _ID_TYPE_RE.match(id_type)
            if not match or not id_number:
                continue  # passports, tax ids, everything that is not a wallet
            asset = match.group(1)

            normalized = detect_and_normalize(id_number)
            if normalized is not None:
                chain, address = normalized.chain, normalized.address
            else:
                # Monero, Zcash and friends: keep the address rather than lose a
                # sanctioned entry to a regex that does not know the format.
                chain = _ASSET_FALLBACK_CHAIN.get(asset, "other")
                address = id_number

            labels.append(Label(
                address=AddressRef(chain=chain, address=address),
                tag=LabelTag.SANCTIONED_OFAC,
                source=SOURCE,
                confidence=CONFIDENCE,
                url=PUBLIC_URL,
                summary=(f"OFAC SDN listing: {name or 'unnamed entry'}"
                         f"{' (' + ', '.join(programs) + ')' if programs else ''}"),
                props={
                    "ofac_asset": asset,
                    "sdn_uid": uid,
                    "sdn_name": name,
                    "sdn_type": sdn_type,
                    "programs": programs,
                    "raw_address": id_number,
                },
            ))
    return labels
