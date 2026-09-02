# EPSS — modelled exploitation probability

**Lake:** `data/lake/epss.sqlite` · **CLI:** `umbra epss` · **Timer:**
`umbra-epss-sync.timer` (daily) · **Source:** FIRST, free, no key

## Why this exists

The wiki carries **CISA KEV** — 1,687 vulnerabilities *known to be exploited* —
and not the other 383,000 published CVEs. That is a deliberate scope choice:
KEV is bounded and actionable, and 384k markdown pages would be a corpus nobody
can clone.

But `cve_lookup` states the limit of that scope in its own docstring:

> No KEV entry does **not** mean no vulnerabilities — nginx has plenty of CVEs
> and zero KEV entries.

EPSS closes exactly that gap. It scores **366,526 CVEs** with the modelled
probability of exploitation in the next 30 days, so the pair reads:

| KEV | EPSS | Meaning |
|---|---|---|
| listed | — | Observed exploited. Act. |
| not listed | 0.94 | Not seen yet; the model says treat it as urgent. |
| not listed | 0.0004 | Genuinely low priority — and now you can *say* so. |

The first real query proved the point. The highest-scoring CVEs **absent** from
KEV were POODLE (CVE-2014-3566), the Log4j DoS (CVE-2021-45105) and KeyTrap
(CVE-2023-50387), all at ~0.99999. A KEV-only view reports "no known exploited
vulnerabilities" for every one of them.

## A prediction is not an observation

This is the rule the module is built around. KEV is a catalogue of things that
**happened**. EPSS is a model output with a version and a score date, which
change daily and disagree with yesterday.

So every score carries `model_version` and `score_date`, and every phrase that
renders one says **"modelled"** — never "is". Conflating them would be the same
failure as reporting an unreachable source as clean.

## Unscored is not low

`score()` returns **None** for a CVE the lake has no row for, and the CLI says
so in words. A CVE published since the last sync has no score; answering `0.0`
would be a confident claim about something nobody has modelled yet.

For the same reason `cve_lookup` **omits** the EPSS keys rather than writing
`epss: None` — a null in a props dict reads as "we looked and it is zero" to
whatever renders it.

## Commands

```bash
umbra epss sync                  # replace the lake from the bulk feed (~2.5 MB gz)
umbra epss status                # rows, model version, score date
umbra epss score CVE-2021-44228  # one CVE
```

## Design notes

- **A lake, not wiki pages.** One number per CVE that changes every day;
  markdown is the wrong shape, and git would carry 366k daily-churning files.
- **Atomic replace.** A half-written lake answers "unscored" for whatever had
  not been inserted, which is indistinguishable from a genuinely unscored CVE.
- **An empty parse refuses to write.** A bad fetch that yields zero rows raises
  rather than wiping a working lake — otherwise one bad morning turns every CVE
  unscored at once.
- **Egress through `GuardedClient`** like any collector. The rules are not
  optional for one module.

## Attribution

EPSS by [FIRST.org](https://www.first.org/epss). Free to use with attribution;
the CLI prints it on every sync.

## Where this shows up: honest wiki misses

The corpus is scoped to CISA KEV. Before EPSS existed, asking the wiki about a
real CVE outside that scope produced:

```
$ umbra lookup CVE-2014-3566
No wiki hits for 'CVE-2014-3566'
Tip: umbra wiki update --path ~/umbra-wiki
```

CVE-2014-3566 is POODLE. It is real, it is famous, and the EPSS lake sitting
next to the wiki scores it **0.99999**. "No hits" plus a tip blaming a stale
corpus — one that was not stale — is the lookup-shaped version of reporting an
unchecked source as clean.

Now (`umbra.wiki.identifiers`, same answer on CLI, `/wiki/search` and
`/api/wiki/search`):

```
CVE-2014-3566 is not in this corpus — that is scope, not absence of the thing.
  The wiki carries the CISA KEV catalogue — vulnerabilities known to be
  exploited — not all 384,910 published CVEs.
  Umbra does know: EPSS 0.99999 (high) — modelled as very likely to be
  exploited in the next 30 days. Model v2026.06.15, scored 2026-08-31.
  authoritative record: https://nvd.nist.gov/vuln/detail/CVE-2014-3566
```

And a number that is not a document is called what it is:

```
RFC99999 does not appear to exist.
  RFC numbers are sequential and currently reach about 9,834.
```
