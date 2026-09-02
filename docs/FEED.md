# Cyber news feed (F1)

**Status:** F1 shipped — RSS ingest, dedupe, `/feed`, `umbra feed`.
**Vault design note:** `Documents/CarlsVault/Projects/OSINT/Umbra-Cyber-News-Feed.md`
**Stage:** S14 · see [CLAUDE-NEXT-STAGES.md](CLAUDE-NEXT-STAGES.md)

Defensive situational awareness inside the same tool as the cases — not a
general RSS reader. Feed items are **signals, not findings**; the UI says so,
because a headline in an investigation tool must not read like a verified fact
about the operator's estate.

## Surfaces

| Where | What |
|-------|------|
| `/feed` | Reverse-chronological, last 24h by default (`?hours=168` for 7 days) |
| `umbra feed ingest` | Poll every enabled source once |
| `umbra feed list [--hours N]` | Recent items in the terminal |
| `umbra feed sources` | Sources with last poll status |
| `umbra feed mute/unmute <url\|name>` | Stop/resume polling a source (stored items are kept) |

## Data

```text
feed_sources(id, name, kind, url UNIQUE, enabled, trust, last_polled_at, last_status, last_error)
feed_items(id, source_id, external_id, url, title, summary,
           published_at, ingested_at, categories, content_hash UNIQUE)
```

Sources live in the database, not in config, so an operator can add or mute one
without a deploy. `umbra.feeds.ingest.DEFAULT_SOURCES` only seeds the starting
pack, and seeding never re-enables a source that was muted.

`categories` is present but unused — F2 fills it, and having the column now
means tagging needs no migration.

## Dedupe

`content_hash` is a SHA-256 of the **canonical** URL and is `UNIQUE`. Canonical
means lower-cased scheme/host, no fragment, no trailing slash, and tracking
parameters (`utm_*`, `fbclid`, …) removed — meaningful query parameters are
kept, because an article id in the query string is the difference between two
different stories.

That is what makes re-polling free and what collapses a story syndicated by two
sources into one row. Each item is committed individually, so a duplicate racing
in from a concurrent poll costs that item, not the batch.

## Scheduling

Ingest runs from `deploy/scripts/feed_ingest.sh` on
`umbra-feed-ingest.timer` (every 30 min), executing `umbra feed ingest` inside
the API container.

**Why a timer and not the durable job queue:** `jobs.case_id` is a `NOT NULL`
foreign key to `cases`, and the project has no migration tooling beyond additive
`create_all` plus hand-written column adds. Putting a *global periodic* task on
a case-scoped queue would mean either inventing a fake case row or running an
unmanaged `ALTER` on the production database. The backup and wiki-sync timers
are the established pattern for scheduled work here, so this follows them.

## Sources

Every URL in the default pack was fetched and parsed before it shipped. Three
plausible candidates did not survive that check:

| Candidate | Why it is not in the pack |
|---|---|
| `cisa.gov/known-exploited-vulnerabilities-catalog.xml` | 404 — KEV has no feed at that path (the wiki corpus imports KEV daily anyway) |
| `msrc.microsoft.com/blog/feed/` | serves an HTML page, not RSS |
| MSRC update guide RSS | parses, but carries ~5,000 CVE entries — a data dump, not news |

That last one is why a single poll can contribute at most
`MAX_ITEMS_PER_POLL = 200` items.

The request `User-Agent` is shaped like a browser token
(`Mozilla/5.0 (compatible; umbra-feed/0.1; +…)`) because `cisa.gov` answers
**403** to a bare token and **200** to this one. It still identifies Umbra and
links to the repo.

## Known: CISA blocks datacenter IPs

Both CISA feeds return **403 from the production VPS** — with any User-Agent,
and `curl` from the host gets the same. It is IP/ASN-based, not a UA problem:
the identical request succeeds from a residential connection. So on prod the
pack effectively runs 3 of 5 sources, and the two CISA rows sit red in
`/feed`'s source table.

Nothing is silently lost: CISA KEV is imported into the wiki corpus daily by
GitHub Actions, which is not blocked. If the red rows are noise,
`umbra feed mute "CISA Alerts"` stops polling them without losing what they
already contributed.

## Failure handling

Sources fail independently — that is the point of having several. A dead host
records `last_status='error'` with the reason and the run continues with the
others; the timer unit never fails on a bad poll, because one flaky publisher is
not an ops incident. A malformed feed parses to zero items rather than raising.

## Ethics

- Public official and reputable sources only. Nothing behind a login or paywall.
- No person-centric or social-stalking queries; aligned with the passive-only
  stance in [BREACH-AND-MONITORING.md](BREACH-AND-MONITORING.md) and
  [ETHICS.md](ETHICS.md).
- Minimal fields stored: title, link, short summary, timestamps. Article bodies
  are linked, never copied.
- Outbound links carry `rel="noopener noreferrer"` so a third-party site is not
  told which internal page the operator came from.

## Not yet built

F2 category tags and filters · F3 entity chips → seed a case · F4 X/social
sources · F5 watch-based alerts · F6 source-trust ranking. `trust` is stored and
displayed but does not yet rank anything.

## CISA is not a source (2026-08-18)

Both CISA feeds sat at `error` with a 403 on the sources page. Nothing in Umbra
was broken: **cisa.gov answers 403 to every user agent** for the advisory XML.
Verified from the production host against `/cybersecurity-advisories/all.xml`,
`/uscert/ncas/alerts.xml` and `/news.xml`, including the browser-shaped UA
`ingest.py` carries for exactly this purpose — that workaround used to get
through and no longer does. Only static files under `/sites/default/files/`
still serve, which is why the KEV corpus import is unaffected.

They are removed from `DEFAULT_SOURCES` and replaced with **CERT-EU Security
Advisories** and **JPCERT/CC**, both verified reachable from the VPS. A
Feedburner mirror of the retired US-CERT feed does answer 200, and is not a
candidate: it is neither official nor current, and this file says official
sources only.

**A block is not an error.** 401/403/406/451 now record `blocked` with a message
saying the publisher refuses automated fetching, and render as a distinct badge.
An `error` invites someone to go fix something; there is nothing to fix, it will
never clear by retrying, and a permanently red row is how you train an operator
to stop reading red rows. A 5xx or a timeout is still an `error`, because that
one might fix itself.

If a publisher relaxes, the next successful poll clears the state on its own.
