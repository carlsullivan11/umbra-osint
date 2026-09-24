"""urlscan.io — search the public corpus. Never submit a scan.

That distinction is the entire design of this collector.

`GET /api/v1/search/` reads scans that other people already ran and chose to
publish. It is a lookup against someone else's archive, and it costs the target
nothing.

`POST /api/v1/scan/` is a different act: it asks urlscan to fetch a URL with a
real browser and, by default, publish the result. That is a live connection to
a host the *visitor* named, made on Umbra's behalf, and it leaves a public
record naming that host. It must never fire from the web front door,
`/reputation` or `POST /run`. This module therefore has **no submit path at
all** — a guarantee a runtime flag cannot make, and one
`test_the_module_contains_no_submit_endpoint` holds in place.

No browser here either. urlscan already ran Chromium; Umbra reads the result.
That is the point of the slice: the capability without the browser farm.

**Absence is unchecked, never "clean".** urlscan indexes what people chose to
scan *and* chose to make public. A URL nobody submitted is unknown, not safe —
and a phishing URL an hour old is precisely the case where the corpus is empty.
A 429 or a missing key means Umbra did not look at all. All three are reported
as different things, because they are.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import urlsplit

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import (
    CollectorResult,
    EntityType,
    EvidenceIn,
)
from umbra.db.schema import Entity

logger = logging.getLogger(__name__)

API_SEARCH = "https://urlscan.io/api/v1/search/"
PERMALINK = "https://urlscan.io/result/{uuid}/"

#: Five is the whole point of a cap here: a heavily-scanned domain can have
#: thousands of public scans and attaching them all would bury the run.
MAX_RESULTS = 5

API_KEY_ENV = "UMBRA_URLSCAN_API_KEY"

_CORPUS_NOTE = (
    "urlscan.io indexes scans that someone chose to run and chose to make "
    "public. A URL nobody has submitted is unknown, not safe."
)


def _api_key() -> str | None:
    return (os.environ.get(API_KEY_ENV) or "").strip() or None


def _quote(value: str) -> str:
    """Wrap a value for the urlscan search DSL.

    The value is attacker-controlled text going into a query language — a URL
    containing ` AND page.domain:bank.example` would otherwise widen the search
    to a domain the operator never asked about. Escaping the quote character
    first means a crafted value cannot close the string and append clauses.
    """
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _query_for(entity: Entity) -> str | None:
    value = (entity.value or "").strip()
    if not value:
        return None
    kind = entity.type
    if kind == EntityType.DOMAIN.value:
        return f"domain:{_quote(value)}"
    if kind == EntityType.URL.value:
        # page.url matches the exact URL as scanned. Falling back to the host
        # would silently answer a different question than the one asked.
        return f"page.url:{_quote(value)}"
    return None


class UrlscanIoCollector(BaseCollector):
    name = "urlscan_io"
    timeout_s = 20
    version = "0.1.0"
    inputs = {EntityType.URL, EntityType.DOMAIN}
    description = (
        "Search the public urlscan.io corpus for existing scans of a URL or "
        "domain (read-only; never submits a scan)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()

        query = _query_for(entity)
        if not query:
            result.notes.append(
                f"urlscan_io: nothing searchable in {entity.value!r} — skipped."
            )
            return result

        key = _api_key()
        headers = {"Accept": "application/json"}
        if key:
            headers["API-Key"] = key

        try:
            resp = ctx.http.get(
                API_SEARCH,
                params={"q": query, "size": str(MAX_RESULTS)},
                headers=headers,
                timeout=self.timeout_s,
            )
        except Exception as exc:  # noqa: BLE001
            from umbra.core.notes import describe_http_failure

            # describe_http_failure never sees the headers, so the key cannot
            # reach a note through this path.
            result.notes.append(describe_http_failure("urlscan_io", exc, API_SEARCH))
            return result

        if resp.status_code == 429:
            # Not an empty corpus — Umbra did not get to look. Rendering this
            # as "no scans found" is how a rate limit becomes a false all-clear.
            result.notes.append(
                "urlscan_io: rate limited (HTTP 429) — the public corpus was "
                "not searched, so this is unchecked rather than unscanned. "
                f"Setting {API_KEY_ENV} raises the limit."
            )
            return result

        if resp.status_code in (401, 403):
            # Deliberately does not echo the response body: urlscan repeats the
            # submitted key in some auth errors, and a note is user-visible.
            result.notes.append(
                f"urlscan_io: search rejected (HTTP {resp.status_code}). If "
                f"{API_KEY_ENV} is set, the key may be invalid or exhausted. "
                "Nothing was checked."
            )
            return result

        if resp.status_code >= 400:
            result.notes.append(
                f"urlscan_io: search failed (HTTP {resp.status_code}) — "
                "unchecked, not unscanned."
            )
            return result

        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            logger.warning("urlscan_io: unparseable search response")
            result.notes.append(
                "urlscan_io: the search response was not valid JSON — "
                "unchecked, not unscanned."
            )
            return result

        rows = payload.get("results") or []
        total = payload.get("total")
        if not isinstance(total, int):
            total = len(rows)

        if not rows:
            result.notes.append(
                f"urlscan_io: no public scan of {entity.value} in the corpus. "
                f"{_CORPUS_NOTE} A URL that has not been scanned is not a URL "
                "that has been cleared."
            )
            return result

        attached = rows[:MAX_RESULTS]
        for row in attached:
            self._attach(result, entity, row)

        # Never a silent cap. "1,200 public scans, showing 5" is a fact about
        # the domain; "5 scans" would be a different and wrong one.
        if total > len(attached):
            result.notes.append(
                f"urlscan_io: {total:,} public scan(s) of {entity.value}; the "
                f"most recent {len(attached)} are attached."
            )
        result.notes.append(_CORPUS_NOTE)
        return result

    def _attach(self, result: CollectorResult, entity: Entity, row: dict) -> None:
        if not isinstance(row, dict):
            return
        uuid = str(row.get("_id") or "").strip()
        if not uuid:
            return

        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        page = row.get("page") if isinstance(row.get("page"), dict) else {}
        verdicts = row.get("verdicts") if isinstance(row.get("verdicts"), dict) else {}
        overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}

        scanned_url = str(task.get("url") or "").strip() or None
        scanned_at = str(task.get("time") or "").strip() or None

        # None, not False. Most public scans carry no verdict at all, and
        # defaulting a missing field to "not malicious" manufactures an
        # all-clear out of silence.
        malicious = overall.get("malicious") if "malicious" in overall else None
        score = overall.get("score") if "score" in overall else None

        summary = f"urlscan.io has a public scan of {scanned_url or entity.value}"
        if scanned_at:
            summary += f" from {scanned_at[:10]}"
        if malicious is True:
            summary += " — urlscan's own verdict marks it malicious"

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="urlscan.io public scan corpus",
                source_url=PERMALINK.format(uuid=uuid),
                summary=summary,
                confidence=0.7,
                raw={
                    "uuid": uuid,
                    "permalink": PERMALINK.format(uuid=uuid),
                    "scanned_url": scanned_url,
                    "scanned_at": scanned_at,
                    "visibility": task.get("visibility"),
                    "page_domain": page.get("domain"),
                    "page_ip": page.get("ip"),
                    "verdict_malicious": malicious,
                    "verdict_score": score,
                    # Linked, never fetched: Umbra does not store third-party
                    # screenshots of arbitrary pages, and the link is as useful.
                    "screenshot": row.get("screenshot"),
                },
                entity_key=entity.norm_key,
            )
        )
