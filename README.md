# Umbra

**Graph-first OSINT for authorized investigations.** Umbra connects public data
sources into a provenance-backed entity graph, scores confidence, and watches
for change — locally, from the command line, with no account and no API keys
required for most of it.

[![PyPI](https://img.shields.io/pypi/v/umbra-osint)](https://pypi.org/project/umbra-osint/)
[![Python](https://img.shields.io/pypi/pyversions/umbra-osint)](https://pypi.org/project/umbra-osint/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> **Lawful use only.** Every case records an `authorization_basis` for audit.
> Umbra is passive and defensive: it does not crawl criminal marketplaces, buy
> stolen data, or provide intrusion capability. Read
> [docs/ETHICS.md](docs/ETHICS.md) and the
> [acceptable use policy](https://umbra-osint.com/legal/aup) before you start.

```bash
pip install umbra-osint
umbra init      # data directory + ethics acknowledgement
umbra doctor    # verify the install before relying on it
```

The distribution is `umbra-osint`; the import package and the commands are
`umbra` and `umbra-worker`.

## What it does

```bash
umbra intent "example.com"          # free text -> a plan you can review
umbra case create -n acme -b own_asset
umbra run <case-id> -d 1            # collect, pivot, score
umbra profile <case-id>             # markdown profile with provenance
umbra graph <case-id> -o acme.graphml
```

- **40 plugin collectors**, most of them key-free — DNS, TLS, RDAP, HTTP,
  Certificate Transparency, git forges, SPARQL, HTML.
- **Entity graph** across 21 types: domain, ip, email, url, username, org,
  person, phone, crypto_address, location, vulnerability, malware, cert, asn,
  mac, repo, technology, breach, paste, nameserver, registrar.
- **Confidence scoring** — multi-factor bands, recomputed after every run, with
  every claim traceable to the evidence that produced it. Independent providers
  combine by noisy-OR, so three sources agreeing outranks one; feeds from the
  same organisation do not corroborate each other. See
  [docs/SCORING.md](docs/SCORING.md).
- **Email header analysis** — `umbra email message.eml` parses the Received
  chain, marks where it stops being trustworthy, and judges SPF/DKIM/DMARC
  alignment from the topmost Authentication-Results only.
- **File ingest** — `umbra <file>` takes .eml, IP and entity lists, CSV, JSON,
  and reads metadata out of images (EXIF), PDFs and Office documents. Nothing
  is collected until you confirm the plan.
- **Public records search** — court opinions via CourtListener, and property
  parcels through a self-growing registry of official county ArcGIS services.
- **Phone reputation** — offline validation plus a moderated community report
  corpus. A number nobody has reported is reported as *unreported*, never as
  clean.
- **Crypto screening** — `umbra crypto screen <address>` against an owned
  OFAC/curated label lake. Offline, no chain API.
- **Owned data lakes** — Umbra ingests primary sources it can then query with no
  external API: Certificate Transparency, the IEEE OUI registry, CISA KEV, the
  abuse.ch malware feeds, DB-IP GeoIP, the Tor directory-authority consensus,
  and an OSM camera/RF corpus.
- **Cyber wiki** — a 4.5k-page corpus with exact-identifier lookup
  (`umbra lookup CVE-2021-44228`), maintained in the separate
  [umbra-wiki](https://github.com/carlsullivan11/umbra-wiki) repo.
- **Watchlist monitor** — DNS/HTTP snapshots and diffs, cron-friendly.
- **Exports** — markdown profile, GraphML, and a full JSON case bundle.

Local-first: SQLite under `~/.umbra` by default, Postgres when you point
`UMBRA_DATABASE_URL` at one.

## Honest limits

These are design positions, not caveats bolted on afterwards. They are the
reason to trust the rest of the output.

- **Absence of a finding is not a clean result.** When a source is unreachable
  Umbra says so rather than reporting nothing found — blocklists, certificate
  logs and vulnerability data are all treated this way, on purpose.
- **DNS blocklists need a local recursive resolver.** Queried through a public
  resolver (1.1.1.1, 8.8.8.8) they refuse the query and answer in a way that
  looks like a listing for *every* address. `umbra doctor` checks this. See
  [docs/DNS-SERVICE.md](docs/DNS-SERVICE.md).
- **An owned lake is only as current as its last sync.** `umbra doctor` reports
  the row count *and the age* of every corpus, because a stale lake answers
  "not listed" with total confidence.
- **The confidence score is evidence strength, not a probability.** It is not
  calibrated against ground truth and cannot be, because the sources Umbra
  reads *are* its ground truth.

## Open core

This repository is the open core: the CLI, the collectors, the scoring engine,
the data lakes and the wiki engine, MIT licensed. The hosted web application at
[umbra-osint.com](https://umbra-osint.com) is a separate, private codebase.
[docs/OPEN-CORE.md](docs/OPEN-CORE.md) describes where the line sits and why.

Core features are free on every surface. `umbra ui` exists as an optional hook
and reports that the web extra is not installed — that is expected here, not a
broken install.

## From source

```bash
git clone https://github.com/carlsullivan11/umbra-osint.git
cd umbra-osint
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Documentation

| Topic | Doc |
|-------|-----|
| Lawful use and ethics | [docs/ETHICS.md](docs/ETHICS.md) |
| Collector reference | [docs/COLLECTORS.md](docs/COLLECTORS.md) |
| Confidence scoring | [docs/SCORING.md](docs/SCORING.md) |
| Intent planner | [docs/INTENT-SEARCH.md](docs/INTENT-SEARCH.md) |
| DNS / DNSBL requirements | [docs/DNS-SERVICE.md](docs/DNS-SERVICE.md) |
| Public records search | [docs/RECORDS.md](docs/RECORDS.md) |
| Email header analysis | [docs/EMAIL-HEADERS.md](docs/EMAIL-HEADERS.md) |
| File and entity ingest | [docs/INGEST.md](docs/INGEST.md) |
| Breach / monitoring boundary | [docs/BREACH-AND-MONITORING.md](docs/BREACH-AND-MONITORING.md) |
| Open core boundary | [docs/OPEN-CORE.md](docs/OPEN-CORE.md) |

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
[SECURITY.md](SECURITY.md) — please do not open a public issue.

## Requires

Python 3.11+. MIT licensed.

- [Guide](https://umbra-osint.com/guide) ·
  [Cyber wiki](https://umbra-osint.com/wiki)
- [Acceptable use](https://umbra-osint.com/legal/aup) ·
  [Terms](https://umbra-osint.com/legal/terms) ·
  [Privacy](https://umbra-osint.com/legal/privacy)
