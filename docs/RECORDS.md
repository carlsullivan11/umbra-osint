# Public records search

`umbra records search NAME` — and `/records` in the web UI — answer one
question: **what public records name this person or company?**

The pieces existed before this and none of them were reachable by typing a name.
Court records lived inside the investigation path, county portals were link
lists a collector walked during a case, property facts were a lake table with no
query in front of them. *"Umbra has a court records collector"* and *"you can
search court records in Umbra"* are very different statements. This is the
second one.

## Four sections, deliberately unequal

| Section | What it is | Coverage |
|---|---|---|
| **Court** | Live from the CourtListener API | Federal + the state courts CourtListener has ingested |
| **Property** | Live from ArcGIS parcel layers | **5 statewide** (AR, CT, NC, VT, WI) + verified county layers |
| **Lake** | What Umbra already holds (obits, kinship, land, corp) | Whatever prior investigations collected |
| **Portals** | *Links*, not records | 75 county packs, 288 URLs |

They are never merged. `record_count` counts the first three and **excludes
portals**, because a link to an assessor is a pointer, not a finding, and
letting links inflate the count would be the lie this codebase keeps refusing to
tell.

## Why an API and not scrapers

Both live sections came from the same realisation, one level apart.

**Court** — CourtListener (Free Law Project) publish a documented REST API that
answers without a token. The alternative on the roadmap was L2 county packs: 75
of 3,143 counties done, each an HTML parser that breaks when a clerk's office
redesigns, each with its own terms-of-service question.

**Property** — there is no national assessor feed, and writing 3,143 scrapers is
not a plan. But **ArcGIS REST is a protocol**, and states already publish
parcels on it. A state aggregates its counties' CAMA rolls into one layer with a
documented `/query` endpoint, and that endpoint speaks the same dialect
everywhere. One client covers every state that publishes one.

### Two tiers of property source

**Curated statewide layers** (5) — hand-probed, each covering a whole state.

**Discovered county layers** — found, probed and verified automatically by
`umbra records sources sync`, stored in the owned registry at
`data/lake/parcel_sources.sqlite`.

The second tier is how this gets past five states. Counties overwhelmingly
publish parcels as ArcGIS feature services, and ArcGIS Online has a public
catalog with ~10,000 items matching "parcels". That catalog is the discovery
surface, not the answer:

> a catalog entry is a claim. a probe is evidence.

About **30% of candidates survive the probe**. The rest fail for reasons kept
apart because they mean different things — no owner field at all (many counties
publish geometry only, deliberately), a dead service, or a field whose *name*
looked right and whose *values* are not names.

Verification has four gates, and a candidate must pass all four:

| Gate | Check |
|---|---|
| 1 | layer metadata loads and exposes a plausibly-owner field |
| 2 | a real owner query answers without an ArcGIS error body |
| 3 | **the returned values look like names** — not house numbers |
| 4 | state/county resolve via the FCC census-area API, or stay NULL |

Gate 3 is the one that earns its keep. `TaxPayerAddr1`, `OWNER_MAIL` and
`OWNERLAB` all match an "ownerish" regex and hold mailing addresses and map
labels. Trusting the field name would have filled the registry with layers that
return confident, wrong answers. On the first live sweep gate 3 caught
`OWNER_MAIL` on a Madison County layer.

Gate 4 is allowed to fail open into NULL on purpose. **A parcel attributed to
the wrong state is worse than one attributed to nowhere**, so an extent that
cannot be resolved is left unresolved rather than approximated from a bounding
box.

The registry stores the publishing ArcGIS account for traceability, but never
shows it: those are frequently named individuals at the county, and surfacing a
private person's username as the attribution on a stranger's property record
helps nobody. The county is the attributor.

```bash
umbra records sources sync --max 100   # bounded, resumable, polite
umbra records sources list --state pa
```

Runs weekly on prod via `umbra-parcel-sources.timer`. Each sweep is bounded,
sleeps between probes, and remembers what it already saw, so coverage grows a
slice at a time instead of hammering hundreds of county servers at once. These
are other people's machines.

**Unscoped searches do not fan out.** Every county layer is its own HTTP round
trip, so a name search with no region searches the statewide layers only and
reports how many county layers naming a region would add. Truncating to an
arbitrary handful and implying that was the whole registry would be the same
silent-cap problem in a new place.

### The five curated layers

Each was **probed before it was added**, not assumed. Five states name the owner
field five different ways — which is exactly why the field map is per-source data
rather than a clever guess.

| State | Owner field | Source |
|---|---|---|
| AR | `ownername` | Arkansas GIS Office (county CAMA rolls) |
| CT | `Owner` | CT Office of Policy and Management |
| NC | `ownname` | NC OneMap |
| VT | `OWNER1` | Vermont Center for Geographic Information |
| WI | `OWNERNME1` | WI Dept. of Administration / SCO |

Adding a sixth state is: probe the endpoint, read its field names, add a
`ParcelSource`. `COVERED_STATES` derives from the registry, so the coverage
claim in the notes cannot drift from the code — there is a test for that.

## Name matching

Assessor rolls write the same person as `DOE, JANE`, `DOE JANE A` and
`JANE DOE`, depending on which county supplied the row. Matching the literal
string would miss most of them, so **each name token becomes its own `LIKE` term
and they are ANDed** — order stops mattering by construction.

User text reaching a SQL `where` clause has exactly one path, `where_clause()`:

- `_SAFE` drops every character that is not name-shaped, so `;` never survives
- runs of `-` collapse to one — `Wal-Mart` is a real owner, `--` is a comment token
- single quotes are doubled, per SQL-92
- tokens under 3 characters are dropped; `Jo` matches most of a state

## What the notes are for

Three failure modes matter more here than anywhere else in Umbra, and each has a
note that fires unconditionally:

**Absence is not a clean record.** No court match means CourtListener has no
match — not that no court does, and not that nothing was sealed or expunged. No
parcel match means *those five states* have no match. A search for a Texas name
returns zero property rows because Umbra does not cover Texas, and that must
never read as "owns no property".

**A name match is not an identity.** Court records name defendants who were
acquitted, parties to suits that settled, and people who merely share a name.
`SMITH, JAMES` is thousands of people. Every row is a candidate with a source
link, never an identity claim — the court collector scores these at 0.35 and
sets `identity_confirmed: False`.

**FCRA.** Using these to decide employment, housing, credit or insurance makes
the operator a consumer reporting agency. Umbra is not one and its output is not
a consumer report. The note fires on every run with results, not once in a terms
page nobody opens.

Two more, because they are easy to misread:

- ArcGIS answers **HTTP 200 with an error body**. That is a source failure and
  is reported as one — treating it as "no parcels" would turn a broken query
  into a clean bill of health.
- The layers are queried **statewide even when the region names a county**,
  because owners hold property across county lines. The note says so rather than
  letting the region label imply a filter that is not there.

## These are homes

A name query returns a real person's residential address and what their county
thinks it is worth. It is public record — states publish it deliberately, and
that is what makes using it lawful — but *lawful* is not *harmless*, so the
caution rides along with the results.

## Commands

```bash
umbra records search "Jane Q Doe"
umbra records search "Jane Q Doe" --region us-ar-benton
umbra records search "Acme LLC" --json
```

Web: `/records` (public, rate limited 20/5min) · JSON: `/v1/records?q=&region=`

Rate limits are tighter than most public routes because every request reaches a
third party's API anonymously. Free Law Project are generous; that is a reason
to be careful, not careless.

## Tests

`tests/test_records_search.py` · `tests/test_records_parcels.py` · `tests/test_records_discover.py`

They assert **properties of the code only** — never live API content and never
operator data. A test asserting "Arkansas returns rows for SMITH" would fail the
day the state reindexes, and a failing test in the deploy gate stops every
unrelated commit behind it. That has happened here before.


## Records into the people lake (2026-09-03)

`county_sources`, `land_facts` and `sor_sources` have had tables and indexes
since the lake was built and held **zero rows** the whole time, while
`records.search` already unified court opinions, parcel owner-name hits and
portal pointers across 100 verified sources and the lake already had a writer
for each kind. Nothing was missing except the wire.

`umbra.people.enrich.enrich_from_records` is that wire.

```bash
umbra records "John Smith" --region AR     # search
# hits are written to the people lake and readable back by name
```

### Two rules it holds

**A portal is not a record.** `RecordHit.is_record` is False for portals; they
point at a place to look. Writing one in would convert *"here is the county's
search page"* into *"this person appears in county records"* — the most
misleading thing a people search can do. Portals are counted as
`portals_skipped` so the omission is visible rather than silent.

**A name hit is not an identification.** A parcel whose owner field reads
"JOHN SMITH" belongs to *a* John Smith. `name_hit` stays a flag on the row; no
record raises a person's confidence on the strength of a string match, and the
returned note says so.

Nothing found is reported as *"the sources searched returned nothing — coverage
is partial, that is unchecked, not an absence of records"*.

### One normaliser, or the rows are unreachable

`upsert_land_fact` computed `person_norm` with the lake's old `_norm_name`
(lowercase + collapse whitespace) while the reader used the new `canonical`
(which also folds diacritics, drops `Jr`/`MD`, and un-reverses `Last, First`).
They agree on "John Smith" and diverge on everything else — a land fact written
for **José García** was stored under `josé garcía`, searched for under
`jose garcia`, and was therefore written, indexed and permanently invisible.

`_norm_name` now delegates to `canonical`, so every table that stores a
normalised name agrees with the search that reads it back. Pinned by a test
that writes and reads each of the four diverging shapes.


## Bulk parcel ingest (2026-09-06)

`records.parcels` asks a county layer about one name. Right for a live lookup,
useless for building a corpus — which is why `land_facts` sat at **zero** for the
life of the project while 100 verified ArcGIS layers went unread.

The fix is the same insight that made `records.parcels` work, one level up.
ArcGIS FeatureServer supports `resultOffset` pagination, and it is open:

| Layer | Rows | maxRecordCount | Pagination |
|---|---|---|---|
| Hillsborough County FL | **367,316** | 2,000 | yes |
| Ramsey County MN | **83,505** | 2,000 | yes |

184 requests owns a county's entire owner roll.

```bash
umbra records parcels-sync --state FL --sources 3 --max-rows 50000
```

Verified against the live Hillsborough endpoint: 6,000 rows, 0 errors.

    Patricia Anne Sevigny Trustee  19859 Angel Ln  Odessa  U-01-27-17-001-000000-00001.0
    Jeffery And Patricia Sevigny   19859 Angel Ln  Odessa  U-01-27-17-001-000000-00001.1

### What the design protects

**Never a silent cap.** A partial county read as a whole one turns an absent
owner into "owns no property". The note says *"6,000 owner record(s) — capped,
the layer reports 367,316"*, and `coverage()` records `rows` against
`reported_total` per county.

**A failed page keeps what came before.** These are county servers, often one
box behind a municipal firewall. A layer that dies at page three must not cost
pages one and two, so errors are collected and the run returns what it got.

**`pause_s` defaults to 0.3s.** 184 back-to-back requests at a county assessor
is rude at best.

**`"None"` is not an address.** ArcGIS ships the literal string for empty
fields; stored naively it becomes a street address nobody lives at.

**These are homes.** Every row is a real person's address and what their county
thinks it is worth. Public record, published deliberately — which is what makes
reading it lawful — but lawful is not harmless, and `SMITH, JAMES` is thousands
of people.

### Court records

Still query-driven, through the CourtListener API, and written into
`county_sources` by `people.enrich`. CourtListener publishes bulk dumps; that is
the same move as this one and has not been made yet.

### `unified_search` reads the owned lake, not live ArcGIS (2026-09-20)

`unified_search` (`src/umbra/people/search.py`) now includes `ParcelLake.lookup`
as a third, separately labelled `parcels` group alongside `people` and the FEC
contributors — same rule as FEC: no identity merge on the owner string, and
`ambiguous` when a name matches more than one state. A miss says county
coverage is partial and the county has not been ingested, never that the person
owns no property, because this lake only knows the counties it has paged. Live,
one-name-at-a-time ArcGIS lookups stay on `umbra records search` / `/records` —
this only ever reads `parcels.sqlite`.


## Coverage against all 3,143 counties (2026-09-06)

Discovery ran five generic catalog queries. The ArcGIS catalog returns what it
likes for a generic term, which is why 3,143 counties produced one or two
verified layers per state — and nothing said *which* counties were missing, so
"expand coverage" had no target and no finish line.

```bash
umbra records parcel-coverage --missing 20     # the ledger, with named gaps
umbra records parcels-discover --counties 200  # targeted queries
umbra records parcels-sync --state FL
```

### Targeted queries

A state name and a county name are the discriminating terms. Verified live:

| Query | Candidates |
|---|---|
| `title:parcels AND "Texas"` | 10 |
| `title:parcels AND "Orange" AND "Texas"` | 2 |

51 state queries run first — a statewide layer covers every county in it, so
NC OneMap is worth 100 counties in one probe. County queries are bounded,
because 3,143 counties is 3,143 catalog requests.

### The ledger

Coverage is counted against the real county list, so an absent owner reads as
*"Orange County, TX is not ingested"* and never as an answer about a person.
A layer probed to zero rows has covered nobody; a layer whose region never
resolved is not a claim about a state.

### The ceiling, stated

Two limits that are real and are not backlog:

**Not every county publishes.** Many use proprietary assessor portals with no
API. The reachable set is the set that publishes on ArcGIS, and no amount of
sweeping changes that.

**Storage.** Measured density is **783 bytes/row**. Hillsborough County alone is
~0.3 GB; all ~150M US parcels would be roughly **117 GB**. The VPS has 54 GB
free, on the same disk as the database and the only backups. Full national
coverage needs a storage decision before it needs more discovery.
