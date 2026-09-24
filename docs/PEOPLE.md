# Person search

**CLI:** `umbra people` · **Web:** `/people`  
**Lake:** `$UMBRA_DATA_DIR/lake/people.sqlite` (backup this path)  
**Collectors:** `obituary_search`, `public_records_portals`, `county_records`,
`court_records` (investigation path)

Both `people.sqlite` and `fec.sqlite` (below) open with `journal_mode=WAL`
and `busy_timeout=5000` (ms) — same values as `nppes.sqlite`/`uls.sqlite` —
so the growth timer's writer and a concurrent web lookup don't block each
other or fail with "database is locked".

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
| Look up a name (people lake only) | `umbra people lookup "Steve Jobs"` | — |
| Search both lakes (people lake + FEC contributors, not identity-merged) | `umbra people find "Steve Jobs"` | `GET /people?q=` · `GET /v1/people?q=` |
| Owned parcel lake (county owner rolls), a third labelled group, not identity-merged | `umbra people find "Steve Jobs"` (parcels table) | `GET /people?q=` · `GET /v1/people?q=` (`parcels`) |
| IRS Form 990 officer/director/trustee lake, a fourth labelled group, not identity-merged | `umbra people find "Steve Jobs"` (officers table) | `GET /people?q=` · `GET /v1/people?q=` (`officers`) |
| FCC ULS radio license lake, a labelled `licensees` group, not identity-merged | `umbra people find "Steve Jobs"` (licensees table) | `GET /people?q=` · `GET /v1/people?q=` (`licensees`) |
| Lake graph dump | `umbra people graph "Steve Jobs"` | `/people?q=` graph panel · `GET /v1/people/graph?q=` |
| Lake status | `umbra people status` | counts on `/people` |
| Recent obit URLs | `umbra people obits` | source-link list on a hit |
| Seed corpus | `umbra people seed` | CLI/operator only |
| Grow lake (Wikidata + wiki extracts) | `umbra people grow --add 400` | CLI/operator + daily timer |
| Fill bulk lakes (FEC closed cycles, NPPES monthly, ULS amateur, IRS 990) | `umbra people fill [--only fec,nppes,uls,990] [--json]` | CLI/operator + weekly timer (`umbra-people-fill.timer`) |
| Confirm kinship | `umbra people confirm NAME -r RELATIVE -v true` | CLI only (no public write) |
| US county coverage | `umbra people coverage` · `docs/US-COUNTY-COLLECTOR-TRACKER.md` | `GET /people/coverage` · `GET /v1/people/coverage` |
| Live investigation | `umbra playbook person_footprint --person "…"` or `umbra intent "person: Jane Doe"` | `/` Search with `person: Full Name` |
| NPPES clinician lookup (separate lake, CLI-only) | `umbra people nppes --zip PATH` | — (follow-up) |
| IRS 990 officer lookup (separate lake, CLI-only) | `umbra people 990 --year YYYY` | — (follow-up) |
| FCC ULS radio license lookup (separate lake, not the FAA N-number lake — see `docs/FAA.md`) | `umbra people uls --zip PATH` (import) · `umbra people find "NAME"` (licensees table, wired into `unified_search`) | `GET /people?q=` · `GET /v1/people?q=` (`licensees`) |

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

## Structured claims, not prose (2026-09-03)

### What was wrong

The lake was filled by asking Wikidata for three things — name, enwiki title,
place of death — then fetching the **Wikipedia article** and running
`parse_obituary_text()` over the prose. An obituary parser looks for
*"of Boca Raton … survived by …"*. Encyclopedia prose has neither, so the
residence pattern matched whatever sat in a similar position.

Measured on prod, 12,001 people, every one sourced from `en.wikipedia.org`:

| Field | Populated | Reality |
|---|---|---|
| residence | 95% | includes `The Manhattan Transfer`, `ARP Instruments`, `Cuba from`, `New York in`, `Andy Warhol's underground films filmed at` |
| occupation | 10% | truncated sentences: *"movies and television spanned 77 years, from 1937 to 2014"* |
| death_date | 3% | |
| birth_place | **0%** | |

The lake was not short of data so much as full of non-facts in its two
best-populated columns.

### The fix

Every one of those fields is a **structured claim** on the same items the
harvest was already selecting. `umbra.people.wikidata` asks for the claims:

`P569` birth · `P570` death · `P19` birth place · `P20` death place ·
`P551` residence · `P106` occupation · `P108` employer ·
`P26` spouse · `P22` father · `P25` mother · `P40` child

Measured against live WDQS on the 2020+ window:

| Field | Before | After |
|---|---|---|
| death_date | 3% | **100%** |
| birth_place | 0% | **96%** |
| death_place | 4% | **92%** |
| occupation | 10% (prose) | **100%** (clean) |
| spouse / children | — | 32% / 20% |

```bash
umbra people claims --add 500      # write from claims (resumes where it stopped)
umbra people claims --reset        # rewind the paging cursor
umbra people repair                # dry run: what prose would be cleared
umbra people repair --apply
```

### Query design

Two constraints, both learned the hard way elsewhere:

**Aggregation.** Occupation, spouse and child are multi-valued. Without
`GROUP_CONCAT`, a person with three occupations and two children returns six
rows and a naive caller multiplies them.

**A bounded subquery.** WDQS times out at 60s. The item set is selected in an
inner `SELECT` with its own `LIMIT`, and only that bounded set is decorated with
the OPTIONAL label joins. Decorating first and limiting afterwards is the shape
that times out.

Labels use explicit `rdfs:label`, not `SERVICE wikibase:label`, because the
label service does not compose with `GROUP BY`. Where a label is missing WDQS
echoes the entity id, so `Q7259` is **dropped** rather than stored — a value
that looks real is worse than an absent one.

### Kinship, and what the source actually says

Wikidata states that a spouse or child **exists**. It does not say whether they
are alive. The lake's two existing buckets hard-code `living=1` (survivors) and
`living=0` (preceded), both of which are claims an obituary supports and a
structured record does not. Relatives therefore go into a third bucket that
writes `living` as **NULL**.

Provenance records `wikidata.org`. The audit found 12,393 of 12,393 sources
naming `en.wikipedia.org` for fields that were regex-guessed rather than read
there.

### The repair sweep, and what it deliberately misses

`umbra people repair` nulls prose-shaped `residence`/`occupation` so the claims
pass can fill them. The bar is asymmetric on purpose: **deleting a real value is
worse than keeping a bad one**, because a later pass can overwrite a bad value
but cannot recover a deleted good one.

So the detector keeps anything it cannot prove is prose. `The Manhattan
Transfer` and `ARP Instruments` survive — nothing separates them from a place
name by shape. That is pinned by a test rather than left as a gap, so nobody
"fixes" it later by loosening the detector and deleting `St. Louis`.

Two rules were removed during development for exactly that reason: a bare
`[.!?]\s` sentence-boundary check deleted `St. Louis`, and a comma-count rule
deleted `singer, actor, musician` — which is precisely the format the new
pipeline writes.


## Name matching (2026-09-03)

`_norm_name` was `" ".join(name.lower().split())`, and lookup was
`norm_name = ? OR norm_name LIKE ? OR full_name LIKE ?`. Two failures:

**It only matched what you typed.** `Ruth Bader Ginsburg` found her;
`Ginsburg, Ruth`, `R. Ginsburg`, `Ruth Ginsburg` and `José García` typed without
the accent all missed. An investigator does not know the stored spelling — not
knowing it is why they are searching.

**`LIKE '%x%'` cannot use an index.** Invisible at 12k rows; at 454k every
search is a full table scan.

`umbra.people.names` canonicalises (case, punctuation, diacritics, `Jr/Sr/III`,
`MD/PhD`, and the `Ginsburg, Ruth` reversal used by government and funeral
records), expands the variants someone might type, and stores them as indexed
keys in `person_name_key`. Lookup is an equality join.

| Query | Finds `Ruth Bader Ginsburg` | Labelled |
|---|---|---|
| `Ruth Bader Ginsburg` | yes | `exact` |
| `Ginsburg, Ruth` | yes | `exact` |
| `Ruth Ginsburg` | yes | `partial` (middle dropped) |
| `R. Ginsburg` | yes | `weak` (initial only) |
| `Franklin` | surname browse | `surname` |

**Strength is judged against the person found, not the key that found them.**
Searching `Ruth Ginsburg` produces `ruth ginsburg` as an exact rendering of the
query — reporting that as `exact` would tell the caller the middle name was
confirmed when it was dropped.

No phonetic matching (Soundex/Metaphone). It collapses genuinely different
surnames, and on a person search a false match is a claim about someone with no
connection to the query.

### Surname browse

A bare surname is a real search and returns results, but labelled `surname` and
capped — so a caller renders *"3 people named Smith"* rather than implying a
match on anyone in particular. It is namespaced (`~sn:smith`) so it can never
collide with someone whose entire recorded name is one word.

An earlier revision refused bare surnames outright. An existing readiness test
caught that as a regression: `lookup_name("Franklin")` was already relied on.

### Key versioning

`NAME_KEY_VERSION` is stored in the lake and the index rebuilds on mismatch.
The first backfill only ran when the key table was **empty**, which silently
skipped lakes indexed by an older key format — adding surname keys left every
already-indexed lake unable to answer a surname search, with no symptom except
results that did not appear. Bump the version when `name_keys` changes.


## Scaling to millions: FEC contributions (2026-09-03)

Wikidata tops out near **454,614** deceased US humans. Millions means living
people, and the largest lawful bulk source carrying an occupation is FEC
campaign finance — name, city, state, ZIP, employer, occupation and date,
published by the FEC as public record for exactly this purpose.

| | |
|--|--|
| Source | `https://www.fec.gov/files/bulk-downloads/{cycle}/indiv{yy}.zip` |
| Size | **3.95 GB** compressed (ZIP64), member `itcont.txt` |
| Format | 21 pipe-delimited columns, no header |
| Lake | `$UMBRA_DATA_DIR/lake/fec.sqlite` (`UMBRA_FEC_DB`, backup this path) |
| CLI | `umbra people fec --download` · `--zip PATH` |

```bash
umbra people fec                 # status
umbra people fec --download      # ~4 GB, then stream-import
```

### Validated against the real file

111,729 rows from the live 2024 archive:

| | |
|---|---|
| parsed as individuals | 111,663 (99.94%) |
| skipped, not `ENTITY_TP=IND` | 66 |
| unique contributors | 68,076 (1.64× dedup on this slice; higher at full scale) |
| city / state / ZIP5 | 99% |
| employer / occupation | 96% |
| date | 100% |

`NAME` arrives as **"JENNINGS, EMILY"** — Last, First — which
`people.names.canonical` already un-reverses, so the source drops straight into
the Phase A matching engine.

### Three constraints in the design

**Memory.** The member expands past 30 GB; the host has 8 GB. Nothing reads the
member — lines are streamed, and aggregation runs in SQLite via `UPSERT` rather
than a Python dict, because ~10M contributors in memory is several GB before any
values attach. A test asserts the module contains no `.read()` or `.readlines()`.

**Aggregated, not transactional.** ~145M contribution rows would be a donations
database. Rows collapse to one record per (name, state, ZIP5) with counts,
totals and a date range. Repeat employers and occupations are collected once,
not once per contribution.

**A separate table.** These are *not* merged into `people`, which holds
deceased notables with obituaries and kinship. Millions of living donors in that
table would destroy what a row there means.

### What a hit is, and is not

The identity key is canonical name + state + ZIP5. It is deliberately coarse:

- two people with the same name in one ZIP **collapse into one row**
- one person who moved **becomes two rows**

Neither is resolvable from this file, and linking them would be an
identification the source does not support. `NOT EMPLOYED` is stored as filed —
nulling it would lose a declared fact and make the field look unasked.

Re-importing the same cycle is a no-op: imports are keyed on the member CRC,
which changes when the FEC republishes and does not when a file is copied.


### Paging (2026-09-04)

The first version had a `LIMIT` and no `OFFSET` over eight fixed year windows.
Eight windows against a 2,000 cap is a hard ceiling of **16,000 rows**, and every
re-run fetched the *same* 16,000 — the lake could never reach the 454,614 the
source holds, and nothing said so.

It now pages with a per-window cursor persisted in the lake's `meta` table, so
runs resume rather than repeat. An empty page marks the window exhausted and
stops asking; looping on a finished window is how a nightly job burns a free
service's quota for nothing.

`pause_s` defaults to 1s. WDQS is a free shared service that rate-limits hard,
and the first version had no delay at all.

Counts are `new` and `updated`, not `written`. The old figure counted upserts,
so a run that re-wrote the same people and added nobody reported the same number
as one that added all of them — a stalled harvest looked like a working one.

Verified live: offsets 0 and 1000 return disjoint sets.


## NPPES (clinicians) (2026-09-20)

CMS's **NPPES** (National Plan and Provider Enumeration System) is a second
FEC-shaped bulk lake: every enumerated healthcare provider's National
Provider Identifier, legal name, practice address and taxonomy (specialty),
published monthly as a lawful public download for exactly this purpose.

| | |
|--|--|
| Source | `https://download.cms.gov/nppes/NPI_Files.html` (direct URL changes monthly — not guessed) |
| Format | zip of `npidata_pfile_*.csv`, header row, columns addressed by name |
| Lake | `$UMBRA_DATA_DIR/lake/nppes.sqlite` (`UMBRA_NPPES_DB`) |
| CLI | `umbra people nppes` (status) · `umbra people nppes --zip PATH` (import) |
| Surfaces | **CLI-only.** Not wired into `unified_search`, intent, or the web UI in this PR — see "not in this PR" below. |

```bash
umbra people nppes                 # status
umbra people nppes --zip PATH      # stream-import a downloaded monthly file
```

**NPI is the identity key, not name+ZIP.** Every provider gets one NPI for
life, so `provider.npi` is a real primary key — a stronger identity than the
FEC lake's coarse name+state+ZIP key. What NPI does **not** fix is the name
itself: a name+NPI hit is a registry row that carries the name on file, not
confirmation that this is the person meant. Miss ≠ not a provider — a name
typed differently than the legal name on record will not match, because this
lake indexes exact canonical form, the same as FEC.

**Individuals only.** Entity Type Code `2` (organizations — clinics,
hospitals, group practices) is skipped on import and counted, the same way
the FEC lake skips non-`IND` entity types. This is a people lake, not a
facility directory.

**Streamed, not read.** The member is read with `csv.DictReader` over a
streamed `TextIOWrapper`, one row at a time — the monthly file's data member
runs hundreds of megabytes to low gigabytes, and nothing here materialises
it. A test asserts the module contains no `.read()` or `.readlines()`, the
same test FEC already has.

**Lookup is an equality index.** `NppesLake.lookup(name, state=)` matches on
`name_canonical`, indexed for equality — not `LIKE '%x%'`, which cannot use
an index at scale.

**A separate table.** NPI rows are not merged into `people` or the FEC
contributor table. A clinician's practice record and a donor record are two
unrelated public-record claims, and merging them would assert a link the
sources do not support.

**Not in this PR.** `unified_search`, the intent planner and the collector
registry are deliberately untouched here — this ticket is "own the lake."
Wiring NPPES into `umbra people find` / intent bundles / `docs/COLLECTORS.md`
is a follow-up. `--download` is not implemented in the CLI (the direct URL
changes every release); fetch the current file manually from the CMS page
above and import with `--zip`.

## IRS Form 990 officers (2026-09-20)

Every tax-exempt organization's **Form 990** lists its officers, directors,
trustees and key employees (Part VII, Section A) by name and title. The IRS
publishes the e-filed originals as public XML on its official bulk-download
page, indexed per filing year — confirmed live against `index_2023.csv`:

| | |
|--|--|
| Source | `https://www.irs.gov/charities-non-profits/form-990-series-downloads` |
| Index | `https://apps.irs.gov/pub/epostcard/990/xml/{year}/index_{year}.csv` — header `RETURN_ID,FILING_TYPE,EIN,TAX_PERIOD,SUB_DATE,TAXPAYER_NAME,RETURN_TYPE,DLN,OBJECT_ID` |
| Filing | `https://apps.irs.gov/pub/epostcard/990/xml/{year}/{OBJECT_ID}_public.xml` (one filing per `OBJECT_ID`) |
| Lake | `$UMBRA_DATA_DIR/lake/irs990.sqlite` (`UMBRA_IRS990_DB`) |
| CLI | `umbra people 990` (status) · `umbra people 990 --year YYYY [--max-files N]` (bounded import) · `umbra people find "NAME"` (officers table, wired into `unified_search`) |
| Surfaces | Wired into `unified_search` as its own labelled `officers` group (issue #22) — `umbra people find`, `GET /people?q=` (HTML), `GET /v1/people?q=` (`officers`). Import (`umbra people 990 --year`) stays CLI-only. |

```bash
umbra people 990                       # status
umbra people 990 --year 2023           # import next 25 (default) filings for 2023
umbra people 990 --year 2023 --max-files 100
```

**Not the Tax Exempt Organization Search SPA.** `apps.irs.gov/app/eos/` is a
search UI over the same underlying data; issue #9 rules it out explicitly.
Everything here reads the official bulk-download index and per-filing XML
instead — a different, scrape-free surface.

**Streamed and bounded, with a resumable cursor.** The IRS also publishes
whole-year bulk zips (`{year}_TEOS_XML_{MM}A.zip`, one to several GB each).
Those are not used: fetching one filing at a time from the index, `--year`
+ `--max-files` at a time, gives a natural row cursor persisted in `meta`
(`cursor:{year}`) without ever holding a multi-GB archive or a full year's
XML in memory. Each filing is parsed with `ElementTree.iterparse`, clearing
elements as they are consumed. No full national dump was fetched in this PR.

**Officer/director fields are the IRS's own MeF schema element names**
(`IRS990.xsd`, `ReturnHeader990x.xsd`), not guessed — `PersonNm`, `TitleTxt`
under `Form990PartVIISectionAGrp`, and `EIN` / `BusinessNameLine1Txt` /
`CityNm` / `StateAbbreviationCd` / `TaxYr` under `ReturnHeader/Filer`. Title
is stored exactly as filed: `"Trustee"` is a filed role, not an identity
claim.

**Identity key is (ein, name_canonical, title).** Two officers who share a
surname — or a whole name — at two different organizations get two separate
rows; nothing here infers they are the same person. `name_canonical` uses
`people.names.canonical`, the same as FEC and NPPES.

**A separate table.** Officer rows are never merged into `people`, the FEC
contributor table, or NPPES — a board seat, a campaign contribution and a
clinical registration are three unrelated public-record claims.

**FCRA note.** A 990 officer/director listing is not a consumer report and
must not be used for credit, employment, insurance, or tenant screening
decisions about the named individual.

**Wired into `unified_search` (issue #22, 2026-09-22).** `Irs990Lake.lookup`
is queried alongside `people`, FEC and parcels and returned as its own
`officers` group on `UnifiedResult` — never merged into another group, same
identity-key discipline as the CLI import. A miss reports `officers_note` as
lake coverage (empty / not imported / name not in filings imported), never
"not an officer" — the lake cannot know that. The intent planner and the
collector registry remain untouched. `--download` of a whole year is
intentionally not offered; only bounded, resumable per-filing import is.

## Filling the bulk lakes (2026-09-24)

`/people` already searched every lake. What it was short of was rows: FEC,
NPPES, ULS and IRS 990 filled only when someone fetched a file by hand, and
only the Wikidata harvest ran on a timer (400/night). `umbra people fill` is one
bounded, resumable pass that a weekly timer runs (`deploy/scripts/people_fill.sh`,
`umbra-people-fill.timer`, Sundays 05:40, under `nice`/`ionice`).

| Source | Unit of work per run | Skipped when |
|---|---|---|
| FEC | next **closed** cycle not yet imported, newest first, back to 2012 (`UMBRA_FILL_FEC_OLDEST`) | every closed cycle is imported |
| NPPES | current monthly full file, link **read from** the CMS index page | that archive is already in the lake |
| ULS | complete `l_amat.zip` (amateur — licensed to individuals) | refreshed within 28 days |
| IRS 990 | up to 200 filings (`UMBRA_FILL_990_FILES`) for this year and last | — (the cursor advances) |

**Never the open FEC cycle.** The FEC lake folds contributions in with an
UPSERT and dedupes on the member CRC. The in-progress cycle is republished
weekly with a new CRC, so importing it on a timer would add every contribution
again each week. Closed cycles are identified by filename and fetched once.

**Never a guessed URL.** The NPPES link must match
`NPPES_Data_Dissemination_<Month>_<Year>[_Vn].zip` on the official page; weekly
and deactivation files are ignored, and no match fails the source rather than
building a URL. *Not verified against the live page from the build sandbox
(egress blocked) — check the first timer run's log.*

**Guarded, bounded, cleaned up.** Downloads re-check the egress guard on every
redirect hop (`httpx`'s `stream(follow_redirects=True)` bypasses
`GuardedClient`'s check — `umbra people fec --download` used it and now uses the
same helper), refuse to start with less than the file size + 15 GB free
(`UMBRA_FILL_MIN_FREE_GB`), land under `$UMBRA_DATA_DIR/tmp/people-fill`, and are
deleted after import whether it succeeded or not. One failing source is reported
and the rest still run; the command exits 1 if any failed.

Enable once on the host after deploy (timers are not enabled by the deployer):

```bash
sudo cp /opt/umbra/app/deploy/systemd/umbra-people-fill.* /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now umbra-people-fill.timer
# first fill now instead of Sunday:
sudo systemctl start umbra-people-fill.service; tail -f /opt/umbra/logs/people-fill.log
```

Each weekly run adds one FEC cycle, so the back catalogue (2024 → 2012, seven
cycles) takes seven weeks unattended; run `umbra people fill --only fec`
repeatedly to go faster, disk permitting.

## Unified search (2026-09-06)

The FEC lake reached **2.25M rows** while being reachable only as *enrichment*
on a person who already existed in `people`. Anyone present only in FEC — which
is nearly everyone in it — returned **nothing at all**. The largest source in
the product was invisible to its own search box.

```bash
umbra people find "John Smith"
umbra people find "John Smith" --state TX
```

`/people?q=John+Smith&state=TX` does the same thing.

### Two rules

**No identity merging.** A Wikidata "Ruth Bader Ginsburg" and an FEC
"GINSBURG, RUTH" filing from DC are two records naming the same string. Neither
source says they are the same person. They return as separate labelled groups,
and a test asserts the fields of one never appear on the other.

**Ambiguity is the answer.** At this scale a common name matches people in
several states. Returning the first 25 rows quietly implies the search found
*someone*; it found many. The result carries `ambiguous`, the state list, and a
note that says so:

> 2 record(s) naming John Smith, across 2 states (MA, TX). These are name
> matches — filter by state to narrow, but a shared name in one state is still
> not one person.

A state filter narrows and does not identify. The FEC grouping key is
(name, state, ZIP5), so **two people with one name in one ZIP are a single row**
and one person who moved is two — stated on the page rather than left implied.

Both lookups are index-backed: `idx_person_name_key` and
`idx_contributor_name`, verified with EXPLAIN QUERY PLAN.

## Federal inmate locator (2026-09-20)

`inmate_locator` copies `sex_offender_registry`'s shape for the BOP's public
inmate locator instead of writing a third variant of the same design:

| | |
|--|--|
| Portal | `https://www.bop.gov/inmateloc/` (JS form — always stored as the source, hit or miss) |
| Search | The form's own JSON endpoint, `POST /PublicInfo/execute/inmateloc` — no Chromium, no captcha bypass. `Captcha: true` in the response is treated as a stop, not solved |
| Lake | `inmate_sources` / `inmate_facts` tables on the same `people.sqlite` as `sor_sources`/`sor_facts` — one schema for both public-registry collectors instead of a fourth database |
| Trust | 0.5 (`COLLECTOR_TRUST["inmate_locator"]`) |
| Candidate | LOCATION (facility) with `kind: "inmate_candidate"`, `identity_confirmed: False`, `manual_confirm: True` |

**First and last, not last alone.** A record only counts as a hit when both
name tokens match the same `InmateLocator` row — every "Smith" in federal
custody is not a hit on one "Smith". `tests/collectors/test_inmate_locator.py`
and `tests/test_inmate_parse.py` pin this against fixtures; nothing here calls
the live BOP endpoint.

**Not a people-finder, not mugshots.** BOP returns no photo from this
endpoint and none is fabricated. A hit is a register number, an age, and a
facility — a lead to confirm, never an address or a face.

**FCRA, every hit.** Same rule as court records: using a register hit to
decide employment, housing, credit or insurance makes the operator a consumer
reporting agency. The note fires on every run that returns a match, not once
in a policy page — see `docs/RECORDS.md`.

**Absence is not clean.** No first+last match covers only current/recent
federal BOP custody — not state prisons, county jails, ICE detention, or
anyone released before this snapshot. The collector says so in the note
rather than implying "not incarcerated".
