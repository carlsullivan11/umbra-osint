# Phone number reputation (Umbra)

**Status:** Phase A + P1 read path + **P2 community write** shipped (2026-08-19).  
**Next:** carrier/CNAM lookup stays behind a paid key and a budget decision.

## What Phase A does

| Input | Behavior |
|-------|----------|
| Phone in **home Search** intent box | Extracted as `EntityType.PHONE` → plan playbook `phone_reputation` → collector `phone_validate` |
| Phone on **`/reputation`** | Classified as phone → depth-0 run with `phone_validate` only |
| Domain / IP | Unchanged multi-source reputation |

## Honest scope

`phone_validate` uses **Google libphonenumber** only:

- E.164 normalize  
- possible / valid under numbering plan  
- region, display formats, plan type  

It does **not**: live HLR, CNAM, carrier API, community spam, person identity.

## Code

| Path | Role |
|------|------|
| `src/umbra/phone/normalize.py` | `normalize_phone`, `phone_facts`, `find_phones` |
| `src/umbra/collectors/phone_validate.py` | Collector |
| `src/umbra/intent/extract.py` | Phone hits |
| `src/umbra/intent/plan.py` | Collectors + playbook |
| `src/umbra/web/routes_reputation.py` | Classify phone |

## Next phases

See `~/.hermes/plans/2026-08-18_192608-umbra-phone-reputation-community.md` and  
`~/.hermes/plans/2026-08-18_193429-umbra-phone-intel-databases-unified-search.md`.

## P1 — the read path (2026-08-19)

`/phone` is a public page: numbering-plan facts plus a community section that,
for now, always says it knows nothing. Reporting is **not open** — the endpoints
do not exist, and a test asserts they 404, because a half-open write path is the
worst version of this feature.

### Why the read path shipped alone

Everything the community section will carry is an allegation about a line
somebody owns, uses for work, or was handed after somebody else gave it up. The
honest order is: publish what Umbra can actually state, publish the policy that
says what is stored and how to object, then open writing.

### Decisions

| Decision | Why |
|---|---|
| Result URL is an **opaque id** | A link shared in a group chat should not carry the number into referrers, browser history and search indexes — and the table cannot be walked by counting. |
| Result pages are **`noindex`** | Umbra publishing "is +1 415 … a scam" into search results would do real harm to whoever answers that phone. |
| **No reports ≠ clean** | The verdict for an unreported number is `unknown` with a note saying so — the same unchecked-is-not-clean rule the collectors follow. |
| **One reporter is never a verdict** | `unconfirmed`, however many agree votes it has. One motivated person is how a personal number gets brigaded, and sockpuppet votes are cheap. |
| **Disputed is a verdict** | Conflicting reports are shown as conflicting, never resolved by majority. |
| Strongest label is **"Likely unwanted"** | Nothing may read as a finding of fact or an accusation of a crime. Tests assert "confirmed", "fraud" and "criminal" never appear in a label. |
| Fixed category enum | "cheater", "ex", "neighbour" are absent by design: they turn a spam database into a harassment tool. Anything outside the list is dropped, not rendered. |
| **Emergency numbers and short codes get no page** | Not spam-report targets; a page implying otherwise is liability with no upside. |
| A lookup row is **pruned after 30 days** unless reported | A search is not a record. Without this the table quietly becomes a log of every number anyone typed. Runs with the case retention sweep. |
| Community tables carry **no `case_id`** | A stranger's allegation must never arrive in a case as collected evidence. A test asserts the column's absence. |
| No nav entry | Linked from `/reputation`. A phone lookup in the main nav invites the reverse-lookup expectation the page then has to refuse. |

### Still to come (P2+)

Report / vote / retract with the dispute route, the `/ops/phone` moderation
queue, and only then FTC complaint data. Carrier/CNAM stays behind a key and a
budget decision, and CNAM display is off unless Carl says otherwise.

## P2 — the write path (2026-08-19)

Reporting, voting, retraction and moderation, in one commit. The moderation
route is not a later phase: opening a public write path about identifiable phone
lines with no way to take content down is how a brigaded personal number becomes
somebody else's problem.

### Every rule maps to a failure

| Failure | Rule |
|---|---|
| One person decides a number's reputation | One report per reporter; one reporter renders `unconfirmed`, never a verdict |
| Sockpuppets vote a number down | One changeable vote per principal, counted apart from reports; votes alone never make a verdict |
| The note becomes a doxxing field | 280 chars, and refused outright if it contains an email, a link, a street address, or SSN/card-shaped digits |
| Somebody reports in anger | Retract, by the reporter, without asking anyone |
| A number is brigaded | Operator hide, on a single report or the whole page, recorded with actor and reason |
| Reporting identifies the reporter | `reporter_key` is an HMAC of the anonymous cookie; the raw cookie and the IP never reach the table |
| Volume | 5 reports/hour, 30 votes/hour — tighter than anything else on the site |

A refused note fails the **whole** write. A report stored without the note the
reporter meant to attach is not the report they made.

The confirmation tick is not decoration: it is where the reporter states what
the AUP asks of them, in the same gesture as the write.

Counters are recomputed from their rows on every write rather than incremented.
A counter that drifts is a number the page states as fact and cannot back up.

### Still deliberately absent

Reverse lookup, people search, bulk export, and any endpoint that lists numbers
to the public. `/ops/phone` is operator-gated and 404s to everyone else.

## Listing lifecycle (2026-08-19)

### Operator seeding

`umbra phone seed --file numbers.txt` files the operator's own known-spam
numbers. They are stored with `source="operator"` and the page says so:

> *N of these came from the operator of this site, not from the public.*

One person's call log rendered as community consensus would be inventing a
crowd. A seeded number reads **Unconfirmed — one report**, because that is what
it is; community reports stack on top and can carry it to a real verdict.

### Listings expire

A listing is a claim about **now**. Spam numbers are recycled, reassigned and
abandoned, so a number reported in March and silent since says little about
whoever answers it today.

`expire_stale_listings` delists numbers with no new report for
`LISTING_ACTIVE_DAYS` (**180**), and runs daily with the case retention sweep.
The page then reads *Previously reported*, with the date of the last report.

**Delisting is not deletion.** The reports stay, the dates stay, `delisted_at`
records when it happened, and a `delist` moderation event records why — "it was
on the list once" has to remain answerable, for the operator and for whoever the
number belongs to. A new report relists it; a vote does not, because one agree
click should not resurrect a listing everyone else has forgotten.

| Command | Does |
|---|---|
| `umbra phone check <number>` | Facts + current community state |
| `umbra phone seed [-f file] [-c category]` | File operator reports |
| `umbra phone expire [--days N]` | Delist stale listings (0 disables) |
| `umbra phone list` | Numbers currently active |

`active_listings` is deliberately not a public endpoint: a dump of the whole
spam database is a scraping and harassment target.

## P3 — FTC Do Not Call complaints (2026-08-19)

A second body of reports that is **not** Umbra's own community: consumer
complaints to the FTC, published by the US government, and explicitly unverified
by them. Rendered as **its own panel**, never folded into the community verdict —
mixing them would blur which group of people said what, and the two are
unverified in different ways.

### The API is the trap; the daily CSV is the source

Both were measured from production before choosing:

| | FTC API | Daily CSV |
|--|--|--|
| Filter by number | **impossible** — unknown params are silently ignored | n/a, you hold the data |
| Page size | 50, whatever `limit` says | ~11,000 rows |
| Pagination | `page` ignored; `offset` walks ~19M records from the **oldest** end | one file per day |
| Row quality | ~2% field-shifted, 6% blank | clean columns |
| `meta.record-total` | returns a *record object*, not a count | n/a |
| API key | required | **none** |
| Effort to index | ~384,000 requests | 26 files |

So the API cannot answer "complaints about this number" at all, and indexing
through it is not feasible. `DNC_Complaint_Numbers_<date>.csv` carries ~11,000
complaints and ~9,900 distinct numbers per day over a 26-day rolling window.

Same trade as abuse.ch and CISA KEV: **the bulk download is the real source and
the API is the thing that looks convenient.**

### Refusal is most of the parser

A row is dropped unless its number passes libphonenumber **validation** — not
merely `possible`, since misaligned digits are often the right length by
accident — and unless a date parses, because a complaint that cannot be dated
cannot be aged or ranked.

Rows are keyed by a **content hash**: the CSV has no row id, and the published
window overlaps every run, so re-reading a day has to cost nothing.

### Not checked ≠ no complaints

`summary()["checked"]` is false until the index holds anything, and the page says
*"Not checked — the FTC complaint index has not been loaded on this instance"*
rather than showing a zero. Same rule as DNSBL, crt.sh and KEV.

### Running it

```bash
umbra phone ftc-sync --days 7
```

`umbra-ftc-sync.timer` runs daily at 18:20 UTC — the FTC publishes on weekdays,
and a government file server does not deserve to be polled harder than its own
cadence. Days already ingested are skipped by `source_day`.

**`UMBRA_FTC_API_KEY` is no longer needed** and is unused. It stays valid for
the API if a future phase ever wants it.
