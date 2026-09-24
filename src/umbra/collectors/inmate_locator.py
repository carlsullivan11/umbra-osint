"""Federal BOP inmate locator — portal + first+last, no Chromium.

The public UI at https://www.bop.gov/inmateloc/ is a JS form, but the form
itself posts to a plain JSON endpoint
(``https://www.bop.gov/PublicInfo/execute/inmateloc``) with no captcha token
required — the same shape as any other documented search API this codebase
already calls directly. That is used here instead of Chromium/Playwright:
one bounded POST, JSON in, no page render.

**A register hit is not identity.** First and last name both on a returned
record is the bar (same as `sex_offender_registry`) — a shared last name
alone is not a hit. Facilities and register numbers are candidates with a
source link, never a confirmed person. No mugshots (BOP does not return one
here), no victim data, no PACER, no state DOC scrapers in this collector.

FCRA: using a docket or inmate hit to decide employment, housing, credit or
insurance makes the operator a consumer reporting agency. Umbra is not one
and this output is not a consumer report — said on every run with results,
not once in a policy page (see ``docs/RECORDS.md``).
"""

from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity
from umbra.people.inmate_parse import parse_inmate_json

PORTAL_URL = "https://www.bop.gov/inmateloc/"
API_URL = "https://www.bop.gov/PublicInfo/execute/inmateloc"

#: Said on every run that returns a candidate, not once in a terms page.
FCRA_NOTE = (
    "A federal inmate locator hit is not a background check. Using it to decide "
    "employment, housing, credit or insurance makes you a consumer reporting "
    "agency under the FCRA. Umbra is not one and this output is not a consumer "
    "report. A register hit is a name match, not a confirmed identity."
)


class InmateLocatorCollector(BaseCollector):
    name = "inmate_locator"
    version = "0.1.0"
    timeout_s = 30
    inputs = {EntityType.PERSON}
    description = (
        "Federal BOP inmate locator JSON search — first+last name on a "
        "returned record = candidate, not identity. No Chromium, no captcha "
        "bypass, no state DOC scrapers."
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        name = (entity.value or entity.display_name or "").strip()
        parts = [p for p in name.replace(",", " ").split() if p]
        if len(parts) < 2:
            result.notes.append("inmate_locator needs first and last name")
            return result

        src = entity_key(EntityType.PERSON, name)
        first, last = parts[0], parts[-1]

        # The portal URL is stored as the human-facing source regardless of
        # what the API call does — 200, 403, timeout, or captcha challenge.
        result.entities.append(
            EntityIn(
                type=EntityType.URL,
                value=PORTAL_URL,
                display_name="BOP Inmate Locator",
                confidence=0.3,
                props={"kind": "inmate_source", "manual_confirm": True},
            )
        )
        result.edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.URL, PORTAL_URL),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.3,
                props={"kind": "inmate_source", "manual_confirm": True},
            )
        )

        ua = getattr(ctx.settings, "user_agent", None) or "UmbraOSINT/0.2"
        timeout = getattr(ctx.settings, "request_timeout_s", 20) or 20
        payload = None
        try:
            resp = ctx.http.post(
                API_URL,
                data={
                    "todo": "query",
                    "output": "json",
                    "inmateNum": "",
                    "nameFirst": first,
                    "nameMiddle": "",
                    "nameLast": last,
                    "race": "",
                    "age": "",
                    "sex": "",
                },
                headers={"User-Agent": ua, "Accept": "application/json"},
                timeout=timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            from umbra.core.notes import describe_http_failure

            result.notes.append(describe_http_failure("bop_inmate_locator", exc, API_URL))
            result.notes.append(
                f"inmate_locator: source stored ({PORTAL_URL}); search unavailable — "
                "unknown rather than clean"
            )
            return result

        if isinstance(payload, dict) and payload.get("Captcha"):
            result.notes.append(
                "inmate_locator: BOP challenged this query with a captcha; "
                f"source stored ({PORTAL_URL}), not solved — unknown rather than clean"
            )
            return result

        parsed = parse_inmate_json(payload, person_name=name, source_url=PORTAL_URL)

        lake = None
        try:
            from umbra.lake.people import PeopleLake

            lake = PeopleLake.from_settings(ctx.settings)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"inmate lake: {exc}")

        try:
            if lake is not None:
                try:
                    lake.upsert_inmate_source(
                        url=PORTAL_URL,
                        person_name=name,
                        name_hit=parsed["name_hit"],
                        total_rows=parsed["total_rows"],
                        parsed=parsed,
                    )
                except Exception as exc:  # noqa: BLE001
                    result.notes.append(f"inmate upsert: {exc}")

            if not parsed["name_hit"]:
                result.notes.append(
                    f"inmate_locator: no first+last register match for {name!r} "
                    f"in {parsed['total_rows']} BOP row(s) returned. Absence covers "
                    "only current/recent federal BOP custody, not state, county, "
                    "ICE, or historical release."
                )
                return result

            for m in parsed["matches"]:
                facility = m.get("facility_name")
                reg_no = m.get("register_number")
                result.evidence.append(
                    EvidenceIn(
                        collector=self.name,
                        source_name="BOP Inmate Locator",
                        source_url=PORTAL_URL,
                        entity_key=src,
                        summary=(
                            f"Inmate locator candidate {name}: register {reg_no or 'unknown'}"
                            + (f", facility {facility}" if facility else "")
                            + " — a name match, not a confirmed identity."
                        )[:280],
                        raw=m,
                        confidence=0.5,
                    )
                )
                if lake is not None:
                    try:
                        lake.upsert_inmate_fact(
                            source_url=PORTAL_URL,
                            person_name=name,
                            register_number=reg_no,
                            age=m.get("age"),
                            facility=facility,
                            facility_code=m.get("facility_code"),
                            release_code=m.get("release_code"),
                            excerpt=None,
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.notes.append(f"inmate fact upsert: {exc}")

                if not facility:
                    continue
                result.entities.append(
                    EntityIn(
                        type=EntityType.LOCATION,
                        value=facility,
                        confidence=0.5,
                        props={
                            "kind": "inmate_candidate",
                            "register_number": reg_no,
                            "source_url": PORTAL_URL,
                            "identity_confirmed": False,
                            "manual_confirm": True,
                        },
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.LOCATION, facility),
                        rel=EdgeType.LOCATED_IN,
                        confidence=0.4,
                        props={"kind": "inmate_candidate", "manual_confirm": True},
                    )
                )

            result.notes.append(
                f"inmate_locator: {len(parsed['matches'])} first+last register "
                f"match(es) for {name!r}; not identity."
            )
            result.notes.append(FCRA_NOTE)
        finally:
            if lake is not None:
                try:
                    lake.close()
                except Exception:
                    pass

        return result
