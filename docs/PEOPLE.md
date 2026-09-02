# Person search

**CLI:** `umbra people` · **Web:** `/people`  
**Lake:** `$UMBRA_DATA_DIR/lake/people.sqlite`  
**Collectors:** `obituary_search`, `public_records_portals`, `county_records`,
`court_records` (investigation path)

This is **not** a commercial people-finder. Umbra stores public obituary/memorial
**source links** plus structured fields and kinship *candidates*.

## Two rules that bind everything here

**A name match is not a person.** The county tracker states it as *name-token ≠
identity*, and it binds hardest on court records: they name defendants who were
acquitted, parties to suits that settled, and everyone who shares those names.
Every person-side collector emits **candidates with source links** at low
confidence, never an identity claim, and says so in the evidence itself.

**FCRA.** Using any of this to decide employment, housing, credit or insurance
makes the operator a consumer reporting agency, with obligations they almost
certainly have not met. Umbra is not a CRA and its output is not a consumer
report. `court_records` repeats that on every run with results, rather than once
in a policy page nobody opens.

**Never:** DMV or driver data (DPPA), PACER logins, captcha bypass, or paywalled
records.

## Surfaces (must match)

| Action | CLI | Web |
|--------|-----|-----|
| Look up a name | `umbra people lookup "Steve Jobs"` | `GET /people?q=` · `GET /v1/people?q=` |
| Lake graph dump | `umbra people graph "Steve Jobs"` | `/people?q=` graph panel · `GET /v1/people/graph?q=` |
| Lake status | `umbra people status` | counts on `/people` |
| Recent obit URLs | `umbra people obits` | source-link list on a hit |
| Seed corpus | `umbra people seed` | CLI/operator only |
| Grow lake (Wikidata + wiki extracts) | `umbra people grow --add 400` | CLI/operator + daily timer |
| Confirm kinship | `umbra people confirm NAME -r RELATIVE -v true` | CLI only (no public write) |
| US county coverage | `umbra people coverage` · `docs/US-COUNTY-COLLECTOR-TRACKER.md` | `GET /people/coverage` · `GET /v1/people/coverage` |
| Live investigation | `umbra playbook person_footprint --person "…"` or `umbra intent "person: Jane Doe"` | `/` Search with `person: Full Name` |

## Seed (required once per data dir)

```bash
umbra people seed
umbra people status
pytest -q tests/test_people_search_readiness.py
```

Wikipedia-first. Find a Grave only when linked from wiki **and** the title matches.
Never hard-code memorial IDs.

## Investigation vs lookup

- **Lookup** (`/people`, `lookup`) — offline lake, no scrape.
- **Investigation** (intent / playbook) — lake hydrate first, then allowlisted public pages, then upsert.

Kinship edges stay `manual_confirm` until an operator T/F.

## Case graph (investigation)

`obituary_search` hydrates the **case graph** from the lake, then live pages:

| Entity | Edge from decedent |
|--------|--------------------|
| PERSON (kin) | `related_to` (`kinship_role`, `manual_confirm`) |
| LOCATION (residence / birth / death / cemetery) | `located_in` |
| ORG (funeral home) | `associated_with` |
| ORG (military) | `member_of` |
| ORG (employer guess) | `works_at` (weak) |
| PERSON (AKA) | `same_as` |
| URL (obituary link) | `mentions` |
| LOCATION (parcel / APN) | `associated_with` (`land_candidate`) |
| ORG (LLC / Inc candidate) | `associated_with` (`corp_officer_candidate`) |
| LOCATION (OSM camera near residence) | `associated_with` (`surveillance`) |
| URL (county portal) | `associated_with` |
| URL (sex-offender registry) | `associated_with` (`sor_source`) |
| LOCATION (registry listed address) | `located_in` (`sor_candidate`) |

## County / land / corporations (investigation)

`county_records` GETs curated assessor/clerk/SOS pages (plus OpenCorporates + EDGAR name URLs). It stores every source link, then parses **candidates**:

| Fact | Graph | Lake |
|------|-------|------|
| Parcel / APN / situs | LOCATION `associated_with` (`land_candidate`) | `land_facts` |
| LLC / Inc near the name | ORG `associated_with` (`corp_officer_candidate`) | `corp_facts` |

Crawl is **httpx + allowlisted same-host follow** (`umbra.core.scrape`), not Crawlee/Playwright. Landing pages often have no name; the crawler follows a few public links whose URL/text mention the last name, then parses those. Cap ~16 pages. No Chromium on the VPS.

Not identity. No PACER, login, e-file, or paid recorder dumps. Name token must appear on the page before a land/corp fact is kept.

Run with location so the right county pack attaches:

```bash
umbra playbook person_footprint --person "Jane Doe" --location "Bentonville, AR" -b training_lab -d 0
```

Kinship T/F is `umbra people confirm` (CLI only). Confirmed lake edges raise confidence.

See also: `docs/CRYPTO-EXPLORATION.md`, `docs/INTENT-SEARCH.md`, `docs/UI.md`.
