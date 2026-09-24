"""Evidence has to say what was found, not that a lookup happened.

Audited across 11,068 production evidence rows: a quarter of them carried no
usable information.

- **1,148 rows (10.4%)** read exactly `RDAP network data for <ip>`. The netname,
  country, allocation range and abuse contact were all fetched, stored in
  `raw`, and left out of the one line a human reads.
- **1,633 rows (14.8%)** were a Python `repr` pasted into user-facing text::

      Cymru origin for 1.1.1.1: [{'asn': '13335', 'prefix': '1.1.1.0/24',
      'cc': 'AU', 'registry': 'apnic', 'raw': '13335 | 1.1.1.0/24 | ...

Both are pure formatting functions here so they can be tested without a network.
"""
from __future__ import annotations

from umbra.collectors.asn_cymru import summarize_origin
from umbra.collectors.rdap_ip import summarize_network

# --- RDAP -------------------------------------------------------------------

CLOUDFLARE = {
    "name": "APNIC-LABS",
    "handle": "AS13335",
    "type": "ASSIGNED PORTABLE",
    "country": "AU",
    "startAddress": "1.1.1.0",
    "endAddress": "1.1.1.255",
    "entities": [{
        "roles": ["abuse"],
        "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "ABUSE APNICAP"],
            ["email", {}, "text", "helpdesk@apnic.net"],
        ]],
    }],
}


def test_rdap_names_the_network():
    s = summarize_network("1.1.1.1", CLOUDFLARE)
    assert "APNIC-LABS" in s


def test_rdap_reports_the_range_and_country():
    s = summarize_network("1.1.1.1", CLOUDFLARE)
    assert "1.1.1.0" in s and "1.1.1.255" in s
    assert "AU" in s


def test_rdap_surfaces_the_abuse_contact():
    """The operationally useful field: who to report this address to."""
    assert "helpdesk@apnic.net" in summarize_network("1.1.1.1", CLOUDFLARE)


def test_rdap_no_longer_says_only_that_data_exists():
    assert summarize_network("1.1.1.1", CLOUDFLARE) != "RDAP network data for 1.1.1.1"


def test_rdap_survives_a_sparse_record():
    s = summarize_network("203.0.113.9", {})
    assert "203.0.113.9" in s
    assert s.strip()


def test_rdap_does_not_leak_a_dict():
    for text in (summarize_network("1.1.1.1", CLOUDFLARE),
                 summarize_network("1.1.1.1", {"name": "X"})):
        assert "{" not in text and "'" not in text


def test_rdap_handles_a_missing_abuse_contact():
    data = dict(CLOUDFLARE, entities=[])
    s = summarize_network("1.1.1.1", data)
    assert "APNIC-LABS" in s
    assert "@" not in s


# --- Team Cymru -------------------------------------------------------------

ORIGIN = [{"asn": "13335", "prefix": "1.1.1.0/24", "cc": "AU",
           "registry": "apnic", "raw": "13335 | 1.1.1.0/24 | AU | apnic | "}]


def test_cymru_reads_as_a_sentence():
    s = summarize_origin("1.1.1.1", ORIGIN)
    assert "AS13335" in s
    assert "1.1.1.0/24" in s


def test_cymru_does_not_leak_a_python_repr():
    """The exact production defect."""
    s = summarize_origin("1.1.1.1", ORIGIN)
    for junk in ("{", "}", "[", "]", "'asn'", "'prefix'"):
        assert junk not in s, f"{junk!r} leaked into user-facing text"


def test_cymru_includes_registry_and_country():
    s = summarize_origin("1.1.1.1", ORIGIN)
    assert "AU" in s
    assert "apnic" in s.lower()


def test_cymru_handles_multiple_origins():
    """A prefix can be announced by more than one AS; that is worth saying."""
    two = ORIGIN + [{"asn": "64496", "prefix": "1.1.1.0/24", "cc": "AU",
                     "registry": "apnic", "raw": ""}]
    s = summarize_origin("1.1.1.1", two)
    assert "AS13335" in s and "AS64496" in s


def test_cymru_handles_no_origin():
    s = summarize_origin("203.0.113.9", [])
    assert "203.0.113.9" in s
    assert "no origin" in s.lower() or "not announced" in s.lower()


def test_cymru_named_as_is_used_when_present():
    rows = [dict(ORIGIN[0], as_name="CLOUDFLARENET")]
    assert "CLOUDFLARENET" in summarize_origin("1.1.1.1", rows)


# --- MOAS: one AS announcing two prefixes is not a hijack -------------------
#
# Found by verifying a real visitor search against Team Cymru. For
# 104.21.21.161 Cymru returns two rows:
#
#     13335 | 104.21.0.0/19 | US | arin | 2014-03-28
#     13335 | 104.21.16.0/20 | US | arin | 2014-03-28
#
# Same AS, an aggregate and a more-specific — completely ordinary Cloudflare
# routing. Production rendered it as:
#
#     announced by AS13335 (CLOUDFLARENET) and AS13335 (CLOUDFLARENET)
#     — prefix 104.21.16.0/20 (multiple origins: multi-homed or a route leak)
#
# The AS is printed twice, and "route leak" is a false hijack signal on a
# security-relevant field. MOAS means *distinct* ASNs announcing one prefix.

TWO_PREFIXES_ONE_AS = [
    {"asn": "13335", "prefix": "104.21.0.0/19", "cc": "US", "registry": "arin",
     "as_name": "CLOUDFLARENET - Cloudflare, Inc., US"},
    {"asn": "13335", "prefix": "104.21.16.0/20", "cc": "US", "registry": "arin",
     "as_name": "CLOUDFLARENET - Cloudflare, Inc., US"},
]

REAL_MOAS = [
    {"asn": "64496", "prefix": "203.0.113.0/24", "cc": "US", "registry": "arin"},
    {"asn": "64497", "prefix": "203.0.113.0/24", "cc": "NL", "registry": "ripencc"},
]


def test_one_as_two_prefixes_is_not_called_a_route_leak():
    s = summarize_origin("104.21.21.161", TWO_PREFIXES_ONE_AS)
    low = s.lower()
    assert "route leak" not in low
    assert "multi-homed" not in low
    assert "multiple origins" not in low


def test_a_repeated_as_is_printed_once():
    s = summarize_origin("104.21.21.161", TWO_PREFIXES_ONE_AS)
    assert s.count("AS13335") == 1


def test_the_most_specific_prefix_is_reported():
    """Both prefixes contain the address; the /20 is the one carrying the route,
    and picking it must not depend on the order Cymru happened to answer in."""
    assert "104.21.16.0/20" in summarize_origin("104.21.21.161", TWO_PREFIXES_ONE_AS)
    assert "104.21.16.0/20" in summarize_origin("104.21.21.161",
                                                list(reversed(TWO_PREFIXES_ONE_AS)))


def test_genuinely_distinct_origins_are_still_flagged():
    """The signal must survive — two different ASNs on one prefix is real MOAS."""
    s = summarize_origin("203.0.113.9", REAL_MOAS)
    assert "AS64496" in s and "AS64497" in s
    assert "origin" in s.lower()


def test_a_single_origin_says_nothing_about_hijacks():
    s = summarize_origin("1.1.1.1", ORIGIN)
    assert "route leak" not in s.lower()
    assert "multiple" not in s.lower()
