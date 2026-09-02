"""50-state + DC public portals (SOS / courts / sex-offender registry).

US-wide coverage is **state-level**, not 3,000 county assessors.
Deep county packs (Benton, Alameda, …) stay in public_records_portals.
"""

from __future__ import annotations

import re
from typing import Any

Portal = dict[str, str]


def _p(name: str, url: str, kind: str) -> Portal:
    return {"name": name, "url": url, "kind": kind}


# abbr, full name, SOS/business, courts, SOR (official; NSOPW remains federal)
_STATES: list[tuple[str, str, str, str, str]] = [
    ("al", "Alabama", "https://www.sos.alabama.gov/business-entities", "https://e2i.alacourt.gov/", "https://app.alea.gov/Community/wfSexOffenderSearch.aspx"),
    ("ak", "Alaska", "https://www.commerce.alaska.gov/web/cbpl/corporations.aspx", "https://courts.alaska.gov/", "https://dps.alaska.gov/SORWeb"),
    ("az", "Arizona", "https://ecorp.azcc.gov/EntitySearch/Index", "https://www.azcourts.gov/", "https://www.azdps.gov/services/public/offender"),
    ("ar", "Arkansas", "https://www.sos.arkansas.gov/business-commercial-services-bcs/business-entity-search", "https://caseinfo.arcourts.gov/", "https://www.ark.org/offender-search/index.php"),
    ("ca", "California", "https://bizfileonline.sos.ca.gov/search/business", "https://www.courts.ca.gov/find-my-court.htm", "https://www.meganslaw.ca.gov/"),
    ("co", "Colorado", "https://www.sos.state.co.us/biz/BusinessEntityCriteriaExt.do", "https://www.courts.state.co.us/", "https://apps.colorado.gov/apps/dps/sor"),
    ("ct", "Connecticut", "https://service.ct.gov/business/s/onlinebusinesssearch", "https://www.jud.ct.gov/", "https://www.communitynotification.com/cap_office_disclaimer.php?office=54567"),
    ("de", "Delaware", "https://icis.corp.delaware.gov/Ecorp/EntitySearch/NameSearch.aspx", "https://courts.delaware.gov/", "https://sexoffender.dsp.delaware.gov/"),
    ("dc", "District of Columbia", "https://corponline.dcra.dc.gov/Home.aspx", "https://www.dccourts.gov/", "https://sexoffender.dc.gov/"),
    ("fl", "Florida", "https://search.sunbiz.org/Inquiry/CorporationSearch/ByName", "https://www.flcourts.gov/", "https://offender.fdle.state.fl.us/offender/sops/home.jsf"),
    ("ga", "Georgia", "https://ecorp.sos.ga.gov/BusinessSearch", "https://georgiacourts.gov/", "https://gbi.georgia.gov/services/georgia-sex-offender-registry"),
    ("hi", "Hawaii", "https://hbe.ehawaii.gov/documents/search.html", "https://www.courts.state.hi.us/", "https://sexoffenders.ehawaii.gov/sexoffender/search.html"),
    ("id", "Idaho", "https://sosbiz.idaho.gov/search/business", "https://isc.idaho.gov/", "https://www.isp.idaho.gov/sor_id/"),
    ("il", "Illinois", "https://apps.ilsos.gov/businessentitysearch/", "https://www.illinoiscourts.gov/", "https://isp.illinois.gov/Sor"),
    ("in", "Indiana", "https://bsd.sos.in.gov/publicbusinesssearch", "https://www.in.gov/courts/", "https://www.icrimewatch.net/indiana.php"),
    ("ia", "Iowa", "https://sos.iowa.gov/search/business/search.aspx", "https://www.iowacourts.gov/", "https://www.iowasexoffender.gov/"),
    ("ks", "Kansas", "https://www.sos.ks.gov/business/business.html", "https://www.kscourts.org/", "https://www.kbi.ks.gov/registeredoffender"),
    ("ky", "Kentucky", "https://web.sos.ky.gov/bussearchnologin/", "https://kycourts.gov/", "https://kspsor.state.ky.us/"),
    ("la", "Louisiana", "https://coraweb.sos.la.gov/commercialsearch/commercialsearch.aspx", "https://www.lasc.org/", "https://www.lsp.org/community-outreach/sex-offender-registry/"),
    ("me", "Maine", "https://icrs.informe.org/nei-sos-icrs/ICRS", "https://www.courts.maine.gov/", "https://sor.informe.org/cgi-bin/sor/index.pl"),
    ("md", "Maryland", "https://egov.maryland.gov/BusinessExpress/EntitySearch", "https://www.mdcourts.gov/", "https://socem.dpscs.maryland.gov/"),
    ("ma", "Massachusetts", "https://corp.sec.state.ma.us/corpweb/CorpSearch/CorpSearch.aspx", "https://www.mass.gov/orgs/massachusetts-court-system", "https://www.mass.gov/orgs/sex-offender-registry-board"),
    ("mi", "Michigan", "https://mibusinessregistry.lara.state.mi.us/", "https://www.courts.michigan.gov/", "https://www.michigan.gov/msp/services/sex-offender-registry"),
    ("mn", "Minnesota", "https://mblsportal.sos.state.mn.us/Business/Search", "https://www.mncourts.gov/", "https://coms.doc.state.mn.us/publicregistrantsearch"),
    ("ms", "Mississippi", "https://corp.sos.ms.gov/corp/portal/c/page/corpBusinessIdSearch/portal.aspx", "https://courts.ms.gov/", "https://state.sor.dps.ms.gov/"),
    ("mo", "Missouri", "https://bsd.sos.mo.gov/BusinessEntity/BESearch.aspx", "https://www.courts.mo.gov/", "https://www.mshp.dps.missouri.gov/CJ38/search.jsp"),
    ("mt", "Montana", "https://biz.sosmt.gov/search/business", "https://courts.mt.gov/", "https://app.doj.mt.gov/apps/svow/"),
    ("ne", "Nebraska", "https://www.nebraska.gov/sos/ccorp/corpsearch.cgi", "https://supremecourt.nebraska.gov/", "https://sor.nebraska.gov/"),
    ("nv", "Nevada", "https://esos.nv.gov/EntitySearch/OnlineEntitySearch", "https://nvcourts.gov/", "https://www.nvsexoffenders.gov/"),
    ("nh", "New Hampshire", "https://quickstart.sos.nh.gov/online/BusinessInquire", "https://www.courts.nh.gov/", "https://business.nh.gov/NSOR/search.aspx"),
    ("nj", "New Jersey", "https://www.njportal.com/DOR/BusinessNameSearch/Search/BusinessName", "https://www.njcourts.gov/", "https://www.njsp.org/sex-offender-registry/"),
    ("nm", "New Mexico", "https://portal.sos.state.nm.us/BFS/online/CorporationBusinessSearch", "https://www.nmcourts.gov/", "https://www.nmsexoffender.dps.nm.gov/"),
    ("ny", "New York", "https://apps.dos.ny.gov/publicInquiry/", "https://www.nycourts.gov/", "https://www.ny.gov/services/search-sex-offender-registry"),
    ("nc", "North Carolina", "https://www.sosnc.gov/online_services/search/by_title/_Business_Registration", "https://www.nccourts.gov/", "https://sexoffender.ncsbi.gov/"),
    ("nd", "North Dakota", "https://firststop.sos.nd.gov/search/business", "https://www.ndcourts.gov/", "https://www.sexoffender.nd.gov/"),
    ("oh", "Ohio", "https://businesssearch.ohiosos.gov/", "https://www.supremecourt.ohio.gov/", "https://ohio.gov/residents/resources/sex-offender-search"),
    ("ok", "Oklahoma", "https://www.sos.ok.gov/corp/corpInquiryFind.aspx", "https://www.oscn.net/", "https://sors.doc.ok.gov/svor/f?p=119:1"),
    ("or", "Oregon", "https://sos.oregon.gov/business/Pages/find.aspx", "https://www.courts.oregon.gov/", "https://sexoffenders.oregon.gov/"),
    ("pa", "Pennsylvania", "https://file.dos.pa.gov/search/business", "https://www.pacourts.us/", "https://www.pameganslaw.state.pa.us/"),
    ("ri", "Rhode Island", "https://business.sos.ri.gov/CorpWeb/CorpSearch/CorpSearch.aspx", "https://www.courts.ri.gov/", "https://www.paroleboard.ri.gov/sexoffender/agree.php"),
    ("sc", "South Carolina", "https://businessfilings.sc.gov/BusinessFiling/Entity/Search", "https://www.sccourts.org/", "https://scor.sled.sc.gov/"),
    ("sd", "South Dakota", "https://sosenterprise.sd.gov/BusinessServices/Business/FilingSearch.aspx", "https://ujs.sd.gov/", "https://sor.sd.gov/"),
    ("tn", "Tennessee", "https://tnbear.tn.gov/Ecommerce/FilingSearch.aspx", "https://www.tncourts.gov/", "https://www.tn.gov/tbi/general-information/tennessee-sex-offender-registry.html"),
    ("tx", "Texas", "https://mycpa.cpa.state.tx.us/coa/", "https://www.txcourts.gov/", "https://publicsite.dps.texas.gov/SexOffenderRegistry"),
    ("ut", "Utah", "https://businessregistration.utah.gov/", "https://www.utcourts.gov/", "https://www.communitynotification.com/cap_main.php?office=54438"),
    ("vt", "Vermont", "https://bizfilings.vermont.gov/online/BusinessInquire", "https://www.vermontjudiciary.org/", "https://www.communitynotification.com/cap_office_disclaimer.php?office=55275"),
    ("va", "Virginia", "https://cis.scc.virginia.gov/", "https://www.vacourts.gov/", "https://sex-offender.vsp.virginia.gov/sor/"),
    ("wa", "Washington", "https://ccfs.sos.wa.gov/", "https://www.courts.wa.gov/", "https://www.icrimewatch.net/index.php?AgencyID=54465"),
    ("wv", "West Virginia", "https://apps.sos.wv.gov/business/corporations/", "https://www.courtswv.gov/", "https://apps.wv.gov/StatePolice/SexOffender"),
    ("wi", "Wisconsin", "https://www.wdfi.org/apps/CorpSearch/Search.aspx", "https://www.wicourts.gov/", "https://appsdoc.wi.gov/public"),
    ("wy", "Wyoming", "https://wyobiz.wyo.gov/Business/FilingSearch.aspx", "https://www.courts.state.wy.us/", "https://wyomingsheriff.com/sex-offenders"),
]

STATE_ABBRS = {row[0] for row in _STATES}
STATE_NAMES = {row[1].lower(): row[0] for row in _STATES}


def state_packs() -> dict[str, list[Portal]]:
    out: dict[str, list[Portal]] = {}
    for abbr, name, sos, courts, sor in _STATES:
        key = f"us-{abbr}"
        out[key] = [
            _p(f"{name} business / SOS search", sos, "business"),
            _p(f"{name} courts", courts, "courts"),
            _p(f"{name} sex-offender registry", sor, "sex_offender"),
        ]
    return out


def sor_portals() -> list[tuple[str, str, str]]:
    """(region_key, title, url) for sex_offender_registry."""
    rows: list[tuple[str, str, str]] = [
        ("us-federal", "NSOPW national search", "https://www.nsopw.gov/"),
        ("us-federal", "NSOPW verification", "https://www.nsopw.gov/en/Search/Verification"),
    ]
    for abbr, name, _sos, _courts, sor in _STATES:
        rows.append((f"us-{abbr}", f"{name} sex-offender registry", sor))
    return rows


def region_places() -> dict[str, str]:
    return {f"us-{abbr}": name for abbr, name, *_ in _STATES}


def detect_state_keys(blob: str, props: dict[str, Any] | None = None) -> list[str]:
    """Map location text → us-xx keys. Comma-state ('Austin, TX') or full name.

    Two-letter codes only after a comma so 'in', 'or', 'me', 'co' in prose
    do not become Indiana/Oregon/Maine/Colorado.
    """
    props = props or {}
    blob = (blob or "").lower()
    found: list[str] = []
    seen: set[str] = set()

    def add(abbr: str) -> None:
        abbr = abbr.lower()
        if abbr in STATE_ABBRS and abbr not in seen:
            seen.add(abbr)
            found.append(f"us-{abbr}")

    explicit = str(props.get("state") or "").strip().lower()
    if explicit in STATE_ABBRS:
        add(explicit)
    elif explicit in STATE_NAMES:
        add(STATE_NAMES[explicit])

    for name, abbr in STATE_NAMES.items():
        if name in blob:
            add(abbr)

    for m in re.finditer(r",\s*([a-z]{2})\b", blob):
        add(m.group(1))

    return found
