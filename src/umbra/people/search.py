"""One search across the people lake and the FEC contributor lake.

The FEC lake reached 2.25M rows while being reachable only as *enrichment* on a
person who already existed in `people`. Anyone present only in FEC — which is
almost everyone in it — returned nothing at all. The largest source in the
product was invisible to its own search box.

Two rules shape the result:

**No identity merging.** A Wikidata "Ruth Bader Ginsburg" and an FEC
"GINSBURG, RUTH" filing from DC are two records that name the same string.
Neither source says they are the same person, and folding them into one row
would be an identification the product invented. They come back as separate,
labelled groups.

**Ambiguity is the answer, not a detail.** At this scale a common name matches
people in many states. Returning the first 25 quietly implies the search found
*someone*; it found many, and saying how many — and where — is the part that
makes the result usable rather than misleading.

A state filter narrows. It does not identify: two John Smiths in Texas are still
two John Smiths.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from umbra.collectors.us_state_portals import STATE_ABBRS

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 25

logger = logging.getLogger(__name__)


@dataclass
class UnifiedResult:
    query: str
    state: str | None = None
    #: City filter applied to the location-bearing registry groups, or None.
    city: str | None = None
    #: Rows from the owned people lake (obituaries, kinship, Wikidata claims).
    people: list[dict[str, Any]] = field(default_factory=list)
    #: Rows from the FEC contributor lake.
    contributors: list[dict[str, Any]] = field(default_factory=list)
    #: Rows from the owned parcel lake (county owner rolls). A separate group,
    #: same as `contributors`: a `ParcelLake` owner string and a person here
    #: name the same string, not the same identity.
    parcels: list[dict[str, Any]] = field(default_factory=list)
    #: Rows from the owned IRS Form 990 officer/director/trustee lake. A
    #: separate group, same as `contributors` and `parcels`: a name on a 990
    #: is an org-officer candidate for one org in one tax year, not the same
    #: identity as a `people` row.
    officers: list[dict[str, Any]] = field(default_factory=list)
    #: More than one distinct location for this name.
    ambiguous: bool = False
    note: str = ""
    #: Ambiguity and miss note for `parcels`, kept separate from `note`
    #: because an absent parcel row means the county was never ingested, not
    #: that the person owns nothing — a claim this lake cannot make.
    parcels_ambiguous: bool = False
    parcels_note: str = ""
    #: Miss note for `officers`, kept separate from `note` for the same
    #: reason as `parcels_note`: an absent 990 row means the officer lake is
    #: empty or not imported for that org/year, never "not an officer".
    officers_note: str = ""
    #: Rows from the NPPES clinician registry, keyed on NPI. A separate group,
    #: same as `parcels`: an NPI record and a person here name the same
    #: string, not the same identity.
    clinicians: list[dict[str, Any]] = field(default_factory=list)
    #: Ambiguity and miss note for `clinicians`, kept separate from `note`
    #: because an absent NPPES row means the lake is empty or not imported,
    #: not that the person is not a clinician — a claim this lake cannot make.
    clinicians_ambiguous: bool = False
    clinicians_note: str = ""
    #: Rows from the FCC ULS radio license lake, keyed on Unique System
    #: Identifier. A separate group, same as `clinicians`: a licensee name on
    #: file with the FCC and a person here name the same string, not the same
    #: identity.
    licensees: list[dict[str, Any]] = field(default_factory=list)
    #: Ambiguity and miss note for `licensees`, kept separate from `note`
    #: because an absent ULS row means the lake is empty or not imported, not
    #: that the person holds no FCC license — a claim this lake cannot make.
    licensees_ambiguous: bool = False
    licensees_note: str = ""
    #: Rows from the federal BOP inmate locator (`inmate_facts`), a separate
    #: group, same as `clinicians`: a register hit names the same string as a
    #: `people` row, not the same identity. Requires first AND last name —
    #: the collector itself never records a hit on less than that.
    inmates: list[dict[str, Any]] = field(default_factory=list)
    #: Miss note for `inmates`, kept separate from `note`. An absent row
    #: means no match was returned, a captcha blocked the query, or only the
    #: portal source was stored — never a claim that this person "is not an
    #: inmate", which this lake cannot make.
    inmates_note: str = ""

    @property
    def total(self) -> int:
        return len(self.people) + len(self.contributors)

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "state": self.state,
            "city": self.city,
            "total": self.total,
            "ambiguous": self.ambiguous,
            "note": self.note,
            "people": self.people,
            "contributors": self.contributors,
            "parcels": self.parcels,
            "parcels_ambiguous": self.parcels_ambiguous,
            "parcels_note": self.parcels_note,
            "officers": self.officers,
            "officers_note": self.officers_note,
            "clinicians": self.clinicians,
            "clinicians_ambiguous": self.clinicians_ambiguous,
            "clinicians_note": self.clinicians_note,
            "licensees": self.licensees,
            "licensees_ambiguous": self.licensees_ambiguous,
            "licensees_note": self.licensees_note,
            "inmates": self.inmates,
            "inmates_note": self.inmates_note,
        }


def _locations(rows: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for r in rows:
        s = (r.get("state") or "").strip().upper()
        if s and s not in out:
            out.append(s)
    return sorted(out)


def unified_search(
    people_lake,
    query: str,
    *,
    state: str | None = None,
    city: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> UnifiedResult:
    """Search both lakes for a name. Never raises.

    `people_lake` is passed in rather than opened here so a caller that already
    has one does not open a second connection; the FEC lake is opened on demand
    because it is optional and large, and its absence must not break a search.

    `state` narrows the location-bearing registry groups (parcels, clinicians,
    licensees) to one US state; `city` narrows the same groups to one city,
    case-insensitively. An empty or invalid value is ignored, never a 422.
    """
    q = (query or "").strip()
    want_state = (state or "").strip().upper() or None
    if want_state and want_state.lower() not in STATE_ABBRS:
        # Not a 2-letter US state code. A typo like "ZZ" must not silently
        # return "no records in ZZ" — ignore it, same as an empty --state.
        want_state = None
    want_city = (city or "").strip().lower() or None
    result = UnifiedResult(query=q, state=want_state, city=want_city)
    if not q:
        return result

    try:
        result.people = people_lake.search_name(q, limit=limit) or []
    except Exception:  # noqa: BLE001
        logger.warning("people lake search failed for %r", q, exc_info=True)
        result.people = []

    try:
        from umbra.lake.fec import FecLake

        fec = FecLake()
        try:
            rows = fec.lookup(q, limit=max(limit * 4, limit))
        finally:
            fec.close()
    except Exception:  # noqa: BLE001 - an optional 4 GB lake is not an outage
        rows = []

    if want_state:
        rows = [r for r in rows if (r.get("state") or "").upper() == want_state]
    result.contributors = rows[:limit]

    try:
        from umbra.lake.parcels import ParcelLake

        parcel_lake = ParcelLake()
        try:
            parcel_rows = parcel_lake.lookup(q, limit=max(limit * 4, limit))
        finally:
            parcel_lake.close()
    except Exception:  # noqa: BLE001 - an optional, multi-GB lake is not an outage
        parcel_rows = []

    if want_state:
        parcel_rows = [r for r in parcel_rows if (r.get("state") or "").upper() == want_state]
    if want_city:
        parcel_rows = [r for r in parcel_rows if (r.get("city") or "").strip().lower() == want_city]
    result.parcels = [
        {
            "owner": r.get("owner"),
            "address": r.get("address"),
            "city": r.get("city"),
            "parcel_id": r.get("parcel_id"),
            "state": r.get("state"),
            "county": r.get("county"),
            "layer_url": r.get("layer_url"),
        }
        for r in parcel_rows[:limit]
    ]

    parcel_states = _locations(result.parcels)
    result.parcels_ambiguous = len(parcel_states) > 1
    if not result.parcels:
        result.parcels_note = (
            f"No parcel record naming {q}. County coverage is partial — this "
            "means the county has not been ingested, and says nothing about "
            "what property, if any, this person holds."
        )
    elif result.parcels_ambiguous:
        result.parcels_note = (
            f"{len(result.parcels)} parcel record(s) naming {q}, across "
            f"{len(parcel_states)} states ({', '.join(parcel_states)}). A name "
            "match on a county owner roll, not an identification."
        )
    else:
        where = f" in {parcel_states[0]}" if parcel_states else ""
        result.parcels_note = (
            f"{len(result.parcels)} parcel record(s) naming {q}{where}. A name "
            "match on a county owner roll, not an identification."
        )

    try:
        from umbra.lake.irs990 import Irs990Lake

        irs990 = Irs990Lake()
        try:
            lake_available = irs990.available
            officer_rows = irs990.lookup(q, limit=max(limit * 4, limit))
        finally:
            irs990.close()
    except Exception:  # noqa: BLE001 - an optional lake is not an outage
        lake_available = False
        officer_rows = []

    result.officers = [
        {
            "ein": r.get("ein"),
            "org_name": r.get("org_name"),
            "name_raw": r.get("name_raw"),
            "title": r.get("title"),
            "city": r.get("city"),
            "state": r.get("state"),
            "tax_year": r.get("tax_year"),
            "source_url": r.get("source_url"),
        }
        for r in officer_rows[:limit]
    ]

    if not result.officers:
        if lake_available:
            result.officers_note = (
                f"No IRS Form 990 officer/director/trustee record naming {q}. "
                "Coverage is per filing year imported — a miss means this "
                "name was not in the filings imported, nothing more."
            )
        else:
            result.officers_note = (
                "IRS Form 990 officer lake is empty or not imported — this "
                "says nothing about whether this person is an officer of any "
                "organization."
            )
    else:
        eins = sorted({r["ein"] for r in result.officers if r.get("ein")})
        where = f" at {len(eins)} organization(s)" if len(eins) > 1 else ""
        result.officers_note = (
            f"{len(result.officers)} IRS Form 990 officer/director/trustee "
            f"record(s) naming {q}{where}. A name on a 990 filing, not an "
            "identification, and never merged with the groups above."
        )

    try:
        from umbra.lake.nppes import NppesLake

        nppes = NppesLake()
        try:
            clinician_rows = nppes.lookup(q, state=want_state, limit=max(limit * 4, limit))
        finally:
            nppes.close()
    except Exception:  # noqa: BLE001 - an optional lake is not an outage
        clinician_rows = []

    if want_city:
        clinician_rows = [r for r in clinician_rows if (r.get("city") or "").strip().lower() == want_city]
    result.clinicians = [
        {
            "npi": r.get("npi"),
            "name_raw": r.get("name_raw"),
            "city": r.get("city"),
            "state": r.get("state"),
            "zip5": r.get("zip5"),
            "taxonomy": r.get("taxonomy"),
            "practice_address": r.get("practice_address"),
            "enumeration_date": r.get("enumeration_date"),
        }
        for r in clinician_rows[:limit]
    ]

    clinician_states = _locations(result.clinicians)
    result.clinicians_ambiguous = len(clinician_states) > 1
    if not result.clinicians:
        result.clinicians_note = (
            f"No clinician registry record naming {q}. The NPPES lake is "
            "empty or not imported — this says nothing about whether this "
            "person is a clinician."
        )
    elif result.clinicians_ambiguous:
        result.clinicians_note = (
            f"{len(result.clinicians)} clinician registry record(s) naming "
            f"{q}, across {len(clinician_states)} states "
            f"({', '.join(clinician_states)}). A name match on the NPPES "
            "registry, not an identification."
        )
    else:
        where = f" in {clinician_states[0]}" if clinician_states else ""
        result.clinicians_note = (
            f"{len(result.clinicians)} clinician registry record(s) naming "
            f"{q}{where}. A name match on the NPPES registry, not an "
            "identification."
        )

    try:
        from umbra.lake.uls import UlsLake

        uls = UlsLake()
        try:
            licensee_rows = uls.lookup(q, state=want_state, limit=max(limit * 4, limit))
        finally:
            uls.close()
    except Exception:  # noqa: BLE001 - an optional lake is not an outage
        licensee_rows = []

    if want_city:
        licensee_rows = [r for r in licensee_rows if (r.get("city") or "").strip().lower() == want_city]
    result.licensees = [
        {
            "fcc_uls_id": r.get("fcc_uls_id"),
            "callsign": r.get("callsign"),
            "name_raw": r.get("name_raw"),
            "city": r.get("city"),
            "state": r.get("state"),
            "zip": r.get("zip"),
            "radio_service": r.get("radio_service"),
            "status": r.get("status"),
        }
        for r in licensee_rows[:limit]
    ]

    licensee_states = _locations(result.licensees)
    result.licensees_ambiguous = len(licensee_states) > 1
    if not result.licensees:
        result.licensees_note = (
            f"No FCC ULS radio license record naming {q}. The lake is empty "
            "or not imported — this says nothing about whether this person "
            "holds an FCC radio license."
        )
    elif result.licensees_ambiguous:
        result.licensees_note = (
            f"{len(result.licensees)} FCC ULS radio license record(s) naming "
            f"{q}, across {len(licensee_states)} states "
            f"({', '.join(licensee_states)}). A name match on a public "
            "license record, not an identification."
        )
    else:
        where = f" in {licensee_states[0]}" if licensee_states else ""
        result.licensees_note = (
            f"{len(result.licensees)} FCC ULS radio license record(s) naming "
            f"{q}{where}. A name match on a public license record, not an "
            "identification."
        )

    name_tokens = [p for p in q.replace(",", " ").split() if p]
    inmate_rows: list[dict[str, Any]] = []
    if len(name_tokens) >= 2:
        try:
            inmate_rows = people_lake.inmate_for_name(q, limit=max(limit * 4, limit)) or []
        except Exception:  # noqa: BLE001 - an optional table is not an outage
            logger.warning("inmate locator lookup failed for %r", q, exc_info=True)
            inmate_rows = []

    try:
        from umbra.collectors.inmate_locator import FCRA_NOTE as INMATE_FCRA_NOTE
    except Exception:  # noqa: BLE001
        INMATE_FCRA_NOTE = (
            "A federal inmate locator hit is not a background check. Using it "
            "to decide employment, housing, credit or insurance makes you a "
            "consumer reporting agency under the FCRA. Umbra is not one and "
            "this output is not a consumer report."
        )

    result.inmates = [
        {
            "person_name": r.get("person_name"),
            "register_number": r.get("register_number"),
            "age": r.get("age"),
            "facility": r.get("facility"),
            "facility_code": r.get("facility_code"),
            "release_code": r.get("release_code"),
            "source_url": r.get("source_url"),
            "identity_confirmed": False,
            "fcra_note": INMATE_FCRA_NOTE,
        }
        for r in inmate_rows[:limit]
    ]

    if not result.inmates:
        if len(name_tokens) < 2:
            result.inmates_note = (
                "The BOP inmate locator requires a first and last name — "
                f"{q!r} is not enough to search."
            )
        else:
            result.inmates_note = (
                f"No BOP inmate locator record naming {q}. A miss here means "
                "no match was returned, a captcha blocked the query, or only "
                "the portal source was stored — coverage is current/recent "
                "federal BOP custody only, in imported/fixture data, never a "
                "claim about state, county, ICE custody, or history."
            )
    else:
        result.inmates_note = (
            f"{len(result.inmates)} BOP inmate locator record(s) naming {q}. "
            "A register name match, not a confirmed identity, and never "
            f"merged with the groups above. {INMATE_FCRA_NOTE}"
        )

    states = _locations(result.contributors)
    # One name, several states. Not one person who moved — this data cannot
    # tell the difference, and the searcher has to.
    result.ambiguous = len(states) > 1

    if result.total == 0:
        result.note = (
            f"No record naming {q} in the corpora searched. Coverage is partial; "
            "that is unchecked, not an absence of the person."
        )
    elif result.ambiguous:
        result.note = (
            f"{result.total} record(s) naming {q}, across {len(states)} states "
            f"({', '.join(states)}). These are name matches — filter by state to "
            "narrow, but a shared name in one state is still not one person."
        )
    else:
        where = f" in {states[0]}" if states else ""
        result.note = (
            f"{result.total} record(s) naming {q}{where}. A name match is not "
            "an identification."
        )
    return result
