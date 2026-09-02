"""OFAC SDN — the sanctions label source.

The primary, official, key-free source of malicious-address labels: 977 digital
currency addresses across 13 assets in the live file, attached to 94 sanctioned
entities.

Two things make this different from every other feed Umbra ingests, and both are
about not asserting more than the list says.

**A sanctions listing is a claim about a point in time.** OFAC *removes* entries
— Tornado Cash was designated in 2022 and delisted in 2025 — and an address
Umbra still labels `sanctioned_ofac` after removal is a false accusation with
legal weight behind it. So a sync is a full-file reconciliation: anything absent
from the current file is marked delisted, with the date, and never silently
kept.

**The list sanctions people, not strings.** A label carries the SDN entity, its
uid and its programmes, so the claim is checkable against the same public file
rather than being a bare "this address is bad".

The asset code is not the chain. OFAC writes `Digital Currency Address - USDT`,
and that address may be ERC-20 or TRC-20 — the chain comes from the address
format, with the OFAC code kept as provenance.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.crypto import ofac  # noqa: E402
from umbra.crypto.types import LabelTag  # noqa: E402

# The exact shape of the live file, trimmed to two entries.
SDN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<sdnList xmlns="http://tempuri.org/sdnList.xsd">
  <sdnEntry>
    <uid>25308</uid>
    <firstName>Xiaobing</firstName>
    <lastName>YAN</lastName>
    <sdnType>Individual</sdnType>
    <programList><program>SDNTK</program></programList>
    <idList>
      <id><uid>16376</uid><idType>Citizen's Card Number</idType><idNumber>421002197703250019</idNumber></id>
      <id><uid>131723</uid><idType>Digital Currency Address - XBT</idType><idNumber>12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h</idNumber></id>
      <id><uid>131724</uid><idType>Digital Currency Address - ETH</idType><idNumber>0x7F367cC41522cE07553e823bf3be79A889DEbe1B</idNumber></id>
    </idList>
  </sdnEntry>
  <sdnEntry>
    <uid>40000</uid>
    <lastName>EXAMPLE ENTITY LLC</lastName>
    <sdnType>Entity</sdnType>
    <programList><program>CYBER2</program><program>DPRK3</program></programList>
    <idList>
      <id><uid>200001</uid><idType>Digital Currency Address - USDT</idType><idNumber>TW6zHzYnQnJvNxACPuVvZzZ8mZ5fPnKq3q</idNumber></id>
    </idList>
  </sdnEntry>
</sdnList>
"""


def test_addresses_are_extracted():
    labels = ofac.parse(SDN_XML)
    assert len(labels) == 3


def test_non_currency_ids_are_ignored():
    """A citizen's card number is not a wallet."""
    labels = ofac.parse(SDN_XML)
    assert not any("421002197703250019" in lab.address.address for lab in labels)


def test_every_label_is_tagged_sanctioned():
    assert {lab.tag for lab in ofac.parse(SDN_XML)} == {LabelTag.SANCTIONED_OFAC}


def test_the_chain_comes_from_the_address_format_not_the_asset_code():
    """OFAC writes `USDT`, which is a token on several chains. The address shape
    is what says which."""
    by_addr = {lab.address.address: lab for lab in ofac.parse(SDN_XML)}
    assert by_addr["12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h"].address.chain == "btc"
    assert by_addr["0x7f367cc41522ce07553e823bf3be79a889debe1b"].address.chain == "eth"
    assert by_addr["TW6zHzYnQnJvNxACPuVvZzZ8mZ5fPnKq3q"].address.chain == "tron"


def test_the_asset_code_is_kept_as_provenance():
    labels = {lab.address.address: lab for lab in ofac.parse(SDN_XML)}
    assert labels["TW6zHzYnQnJvNxACPuVvZzZ8mZ5fPnKq3q"].props["ofac_asset"] == "USDT"


def test_evm_addresses_are_lowercased_for_lookup():
    """Mixed-case EIP-55 input must find a lowercase-keyed label."""
    labels = [lab for lab in ofac.parse(SDN_XML) if lab.address.chain == "eth"]
    assert labels[0].address.address == labels[0].address.address.lower()


def test_the_label_names_the_sanctioned_party():
    """"This address is bad" is not checkable. "Belongs to SDN uid 25308,
    Xiaobing YAN, programme SDNTK" is."""
    label = next(lab for lab in ofac.parse(SDN_XML)
                 if lab.address.chain == "btc")
    assert "YAN" in label.props["sdn_name"]
    assert label.props["sdn_uid"] == "25308"
    assert "SDNTK" in label.props["programs"]


def test_multiple_programmes_are_all_kept():
    label = next(lab for lab in ofac.parse(SDN_XML) if lab.address.chain == "tron")
    assert set(label.props["programs"]) == {"CYBER2", "DPRK3"}


def test_the_label_links_back_to_the_public_list():
    """The claim has to be checkable against the same file anyone can download."""
    label = ofac.parse(SDN_XML)[0]
    assert label.url and label.url.startswith("https://")
    assert label.source.lower().startswith("ofac")


def test_sanctions_labels_are_high_confidence():
    """This is a government list, not a crowdsourced tag."""
    assert all(lab.confidence >= 0.95 for lab in ofac.parse(SDN_XML))


def test_junk_xml_is_not_a_crash():
    for junk in ("", "   ", "<notxml", "<sdnList></sdnList>"):
        assert ofac.parse(junk) == []


def test_an_entry_with_no_crypto_id_yields_nothing():
    xml = SDN_XML.replace("Digital Currency Address - XBT", "Passport")
    xml = xml.replace("Digital Currency Address - ETH", "Passport")
    xml = xml.replace("Digital Currency Address - USDT", "Passport")
    assert ofac.parse(xml) == []


def test_an_unrecognised_address_format_is_still_recorded():
    """Monero and Zcash addresses do not match the EVM/BTC/TRON patterns, and
    dropping them would silently lose sanctioned addresses."""
    xml = SDN_XML.replace(
        "<idNumber>12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h</idNumber>",
        "<idNumber>4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge</idNumber>")
    xml = xml.replace("Digital Currency Address - XBT",
                      "Digital Currency Address - XMR")
    labels = [lab for lab in ofac.parse(xml) if lab.props.get("ofac_asset") == "XMR"]
    assert len(labels) == 1
    assert labels[0].address.chain in {"xmr", "other"}
