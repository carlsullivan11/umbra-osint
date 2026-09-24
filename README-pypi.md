# Umbra

**Graph-first OSINT for authorized investigations.** Umbra connects public data
sources into a provenance-backed entity graph, scores confidence, and watches
for change — locally, from the command line, with no account and no API keys
required for most of it.

> **Lawful use only.** Every case records an `authorization_basis` for audit.
> Umbra is passive and defensive: it does not crawl criminal marketplaces, buy
> stolen data, or provide intrusion capability. Read the
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

- **47 plugin collectors**, most of them key-free — DNS, TLS, RDAP, HTTP,
  Certificate Transparency, git forges, SPARQL, HTML.
- **Entity graph** across 22 types: domain, ip, email, url, username, org,
  person, phone, crypto_address, location, vulnerability, malware, cert, asn,
  mac, aircraft, repo, technology, breach, paste, nameserver, registrar.
- **Confidence scoring** — multi-factor bands, recomputed after every run, with
  every claim traceable to the evidence that produced it.
- **Email header analysis** — `umbra email message.eml` parses the Received
  chain, marks where it stops being trustworthy, and judges SPF/DKIM/DMARC
  alignment from the topmost Authentication-Results only.
- **File ingest** — `umbra <file>` takes .eml, IP and entity lists, CSV, JSON,
  and reads metadata out of images (EXIF), PDFs and Office documents. Nothing
  is collected until you confirm the plan.
- **Alert triage**: `umbra triage alert.json` takes an indicator, a SIEM
  alert (ECS, Suricata EVE, Wazuh, Zeek) or an IOC list, enriches the external
  side passively, and answers *escalate*, *needs analyst* or *suggest close*
  using TypeSafe's Jev with **your own key**. Internal hosts, users and
  addresses never leave the machine. Nothing is ever closed for you.
- **Phone reputation** — offline validation plus a moderated community report
  corpus. A number nobody has reported is reported as *unreported*, never as
  clean.
- **Crypto screening** — `umbra crypto screen <address>` against an owned
  OFAC/curated label lake. Offline, no chain API.
- **Owned data lakes** — Umbra ingests primary sources it can then query with no
  external API: Certificate Transparency, the IEEE OUI registry, CISA KEV, the
  abuse.ch malware feeds, DB-IP GeoIP, and an OSM camera/RF corpus.
- **Cyber wiki** — a 4.5k-page corpus with exact-identifier lookup
  (`umbra lookup CVE-2021-44228`). CVE coverage is **every entry in the CISA
  Known Exploited Vulnerabilities catalogue** — not all published CVEs, which
  is a deliberate scope choice. `umbra epss score CVE-…` covers the rest with
  FIRST's modelled exploitation probability, so "not in KEV" stops meaning
  "no information".
- **Watchlist monitor** — DNS/HTTP snapshots and diffs, cron-friendly.
- **Exports** — markdown profile, GraphML, and a full JSON case bundle.
- **Blocklist output** — malware domain/IP and adult-content feeds in
  Pi-hole/AdGuard format, built from the owned lakes.

Local-first: SQLite under `~/.umbra` by default, Postgres when you point
`UMBRA_DATABASE_URL` at one.

## Honest limits

- **Absence of a finding is not a clean result.** When a source is unreachable
  Umbra says so rather than reporting nothing found — blocklists, certificate
  logs and vulnerability data are all treated this way, on purpose.
- **DNS blocklists need a local recursive resolver.** Queried through a public
  resolver (1.1.1.1, 8.8.8.8) they refuse the query and answer in a way that
  looks like a listing for every address. `umbra doctor` checks this.
- **An owned lake is only as current as its last sync.** `umbra doctor` reports
  the row count *and the age* of every corpus, because a stale lake answers
  "not listed" with total confidence.
- **Triage sees indicators, not behaviour.** It judges who an address or
  domain is, not what a process did on your endpoint, and bare IPs mostly land
  on "needs analyst". Without a Jev key nothing unlisted is suggested for
  closing.
- **The hosted web application is not in this package.** The CLI is the open
  core; the hosted product runs at [umbra-osint.com](https://umbra-osint.com).

## Requires

Python 3.11+. MIT licensed.

- [Guide](https://umbra-osint.com/guide)
- [Cyber wiki](https://umbra-osint.com/wiki)
- [Acceptable use](https://umbra-osint.com/legal/aup) ·
  [Terms](https://umbra-osint.com/legal/terms) ·
  [Privacy](https://umbra-osint.com/legal/privacy)
