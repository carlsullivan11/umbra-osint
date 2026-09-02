"""Court records via the CourtListener API — not by scraping courthouses.

Umbra already listed CourtListener at L0 of the county tracker. It was a
**link**: `courtlistener.com/?type=r&q={name}`, for the operator to click. The
data was never retrieved.

That is the single largest gap in the public-records surface, and closing it is
also the cheapest thing here. Free Law Project publish a documented REST API
that answers without a token and covers federal courts plus a growing set of
state ones — 55,833 opinions for one case-name query, 100,617 RECAP dockets for
one company. Compare the alternative that was on the roadmap: L2 county packs,
75 of 3,143 counties done, each an HTML parser that breaks when a clerk's office
redesigns, each carrying its own terms-of-service question.

An API someone built for this purpose beats scraping on every axis that matters
— legality, reliability, coverage, and the maintenance nobody wants.

**A name match is not a person.** The county tracker already states the rule —
*name-token ≠ identity* — and it matters more here than anywhere else in the
codebase. Court records name defendants who were acquitted, parties to civil
suits that settled, and people who share a name with all of them. So this
collector emits **candidates with source links**, never an identity claim, and
every piece of evidence says so.

**FCRA.** Court records are exactly where someone is tempted to screen a job
applicant or a tenant. Doing that makes the operator a consumer reporting agency
under the Fair Credit Reporting Act, with obligations they almost certainly have
not met. Umbra is not a CRA, its output is not a consumer report, and the notes
say so on every run rather than once in a terms page nobody opens.

Source: https://www.courtlistener.com/api/rest/v4/ (Free Law Project, CC-BY).
"""
from __future__ import annotations

import re
from urllib.parse import quote_plus

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import (
    CollectorResult,
    EdgeIn,
    EdgeType,
    EntityIn,
    EntityType,
    EvidenceIn,
)
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

API = "https://www.courtlistener.com/api/rest/v4/search/"
SITE = "https://www.courtlistener.com"

#: Opinions (published decisions) and RECAP (federal docket data). Two very
#: different things: an opinion is a court's published reasoning, a docket entry
#: is the existence of a filing. Kept apart because they mean different things
#: about a person.
SEARCH_TYPES = (("o", "opinion"), ("r", "docket"))

#: Per type. A name that returns hundreds of dockets is a common name, and
#: dumping them all into a graph buries the case rather than informing it.
MAX_PER_TYPE = 8

#: Said on every run, not once in a policy page.
FCRA_NOTE = (
    "Court records are not a background check. Using them to decide employment, "
    "housing, credit or insurance makes you a consumer reporting agency under "
    "the FCRA. Umbra is not one and this output is not a consumer report."
)

_NAME_OK = re.compile(r"^[\w .,'\-]{3,80}$", re.U)


class CourtRecordsCollector(BaseCollector):
    name = "court_records"
    version = "0.1.0"
    timeout_s = 45
    inputs = {EntityType.PERSON, EntityType.ORG}
    description = (
        "Federal and state court opinions + RECAP dockets from the CourtListener "
        "API (Free Law Project, no key). Name candidates with source links — "
        "never an identity claim."
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        query = (entity.value or "").strip()

        if not _NAME_OK.match(query):
            result.notes.append(
                f"court_records: {query!r} is not a name-shaped query — skipped "
                "rather than sending it to a public API"
            )
            return result

        src_key = entity.norm_key
        total_seen = 0

        for code, label in SEARCH_TYPES:
            try:
                resp = ctx.http.get(
                    API,
                    params={"q": f'"{query}"', "type": code},
                    headers={"Accept": "application/json"},
                    timeout=20,
                )
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001
                from umbra.core.notes import describe_http_failure

                result.notes.append(describe_http_failure(f"courtlistener_{label}", exc, API))
                continue

            count = int(payload.get("count") or 0)
            rows = (payload.get("results") or [])[:MAX_PER_TYPE]
            total_seen += count

            if count and not rows:
                continue

            # Never a silent cap: a name with 900 dockets is a fact about the
            # name, and truncating to 8 without saying so would misrepresent it.
            if count > len(rows):
                result.notes.append(
                    f"court_records: {count:,} {label} result(s) for {query!r}; "
                    f"the first {len(rows)} are attached. A large count usually "
                    f"means a common name, not a prolific litigant."
                )

            for row in rows:
                self._attach(result, src_key, query, row, label)

        if total_seen == 0:
            # Absence here is weak evidence and must not read as a clearance.
            result.notes.append(
                f"court_records: no CourtListener match for {query!r}. That covers "
                "federal courts and the state courts CourtListener has ingested — "
                "not every court in the country, and not sealed or expunged "
                "matters. Absence is not a clean record."
            )
        else:
            result.notes.append(FCRA_NOTE)

        return result

    def _attach(self, result: CollectorResult, src_key: str, query: str,
                row: dict, label: str) -> None:
        case_name = (row.get("caseName") or row.get("case_name_full") or "").strip()
        court = (row.get("court") or row.get("court_citation_string") or "").strip()
        filed = (row.get("dateFiled") or row.get("dateArgued") or "").strip()
        path = (row.get("absolute_url") or "").strip()
        url = f"{SITE}{path}" if path.startswith("/") else (path or SITE)

        if not case_name:
            return

        result.entities.append(EntityIn(
            type=EntityType.URL,
            value=url,
            # Deliberately low. This is a name appearing in a record, which is a
            # lead; treating it as 0.9 would let a namesake harden into a fact
            # after one scoring pass.
            confidence=0.35,
            props={
                "source": "courtlistener",
                "record_type": label,
                "case_name": case_name,
                "court": court,
                "date_filed": filed,
                "matched_name": query,
                "identity_confirmed": False,
            },
        ))
        result.edges.append(EdgeIn(
            source_key=src_key,
            target_key=entity_key(EntityType.URL, url),
            rel=EdgeType.MENTIONS,
            confidence=0.35,
            props={"source": "courtlistener", "record_type": label},
        ))
        result.evidence.append(EvidenceIn(
            collector=self.name,
            source_name=f"CourtListener {label} (Free Law Project)",
            source_url=url,
            summary=(
                f"The name {query!r} appears in {case_name}"
                + (f" ({court})" if court else "")
                + (f", filed {filed}" if filed else "")
                + " — a name match, not a confirmed identity."
            ),
            confidence=0.35,
            raw={k: row.get(k) for k in
                 ("caseName", "court", "dateFiled", "docketNumber", "absolute_url")
                 if row.get(k)},
        ))
