# Collector reference

**Source of truth for installed collectors.** Generated from code behavior; keep in sync when adding collectors.

**Count: 47** (verify: `umbra collectors`)

## Full table

| Name | Inputs | Description | Key / notes |
|------|--------|-------------|-------------|
| `asn_cymru` | ip | ASN/BGP via Team Cymru DNS | No key |
| `ip_geo` | ip | City/country/lat-lon from **owned** DB-IP City Lite lake | **Offline**; fill with `umbra geoip sync` (free CC-BY). Unsynced = unchecked |
| `cve_lookup` | technology | Known-exploited CVEs (CISA KEV) affecting a product, from the **owned** corpus | **No API, no key**; bounded to KEV — absence means "not known-exploited", not "no CVEs" |
| `crtsh` | domain | CT subdomains via crt.sh (multi-query + retry) | Public HTTP; flaky under load |
| `ct_lake` | domain | CT subdomains + certs from the **owned** corpus (`umbra ct`), with SHA-256 fingerprints and issuing CAs | **No external API**; carries `fingerprint_sha1` for SSLBL join. **CT logs shard by year** — `KNOWN_LOGS` must be refreshed each January or the corpus silently freezes (`tests/test_ct_log_freshness.py` enforces it) |
| `people_lake` | person | Owned person corpora — obituary/kinship people lake + **2.25M FEC contributor records** | **Offline**, no key. S1a/H3 — no collector imported `FecLake`, so the largest corpus Umbra owns was unreachable from a case. Evidence only: an FEC filing does not establish that a named person works somewhere. States the ambiguity count, because a shared name is not one person |
| `email_profile` | email | Role account, disposable provider, provider class, and the form the address delivers to | **Offline**, no key. U6 — `EMAIL` had 3 collectors and a free-mail search returned 51 rows about the provider's hosting and 2 about the address |
| `ddg_search` | domain, org, person, username | DuckDuckGo HTML search | Weak links; low score weight |
| `dns_email_auth` | domain | SPF/DMARC/DKIM/MX + MTA-STS/TLS-RPT/BIMI/DNSSEC | DNS only (+ best-effort MTA-STS policy fetch) |
| `dns_resolve` | domain | A/AAAA/MX/NS/TXT/CNAME | DNS only |
| `edgar_search` | org, person | SEC EDGAR public browse/EFTS | No key; may HTTP 403 from some IPs |
| `email_split` | email | Split to domain + local username | Local |
| `github_commits` | username | Repos/emails via HTML + Atom + git log | No GitHub API |
| `github_user` | username | Profile + repos | Optional `UMBRA_GITHUB_TOKEN` |
| `gravatar` | email | Avatar/profile from email MD5 | No key |
| `hibp_breach` | email | Have I Been Pwned breaches | `UMBRA_HIBP_API_KEY` |
| `html_links` | domain, url | Emails + social links from HTML | No key |
| `http_probe` | domain, url | Status, title, headers + **server stack fingerprint** (header-name order hash, `Server`, same-origin favicon hash) | No key. Header **names** only, never values. Fingerprint ≠ identity; a CDN collides every site behind it |
| `lookalike_domains` | domain | Typosquat generation + DNS resolve | Seeds preferred; noisy if overused |
| `mac_oui` | mac | MAC → IEEE registrant from the **owned** OUI lake | **Offline, no key** |
| `faa_registry` | aircraft | US **N-number → registrant of record + airframe** from the **owned** FAA Releasable Aircraft Database | **Offline, no key.** Registrant ≠ operator ≠ pilot. A miss is *unchecked*, never "not registered" (49 U.S.C. § 44114(b) withholding). Org registrant is a 0.6 candidate; an individual gets no PERSON entity. See `docs/FAA.md` |
| `urlscan_io` | url, domain | **Existing public scans** from the urlscan.io corpus — uuid, permalink, scan time, verdict when present | **Read-only search.** Never POSTs a scan (no code path); no Chromium; no TCP to the target. Miss / 429 / bad key = *unchecked*, never "clean". Screenshot linked, not stored. Cap 5. Optional `UMBRA_URLSCAN_API_KEY`. See `docs/URLSCAN.md` |
| `internetdb` | ip | **Shodan InternetDB index** — ports, hostnames, CPEs, tags, CVEs Shodan already observed | **Not a scan.** No key; only host contacted is `internetdb.shodan.io`; nothing sent to the address. 404/429 = *unchecked*, never "no open ports". IPv6/private/CGNAT skipped. CVE list is inferred from version banners. See `docs/INTERNETDB.md` |
| `phone_validate` | phone | E.164 validate/format via libphonenumber | **Offline, no key**. Not live line, CNAM, or spam verdict |
| `malware_infra` | domain, ip | Malware URLs + C2 attribution (URLhaus, ThreatFox, Feodo) from the **owned** abuse.ch lake | **No network** at collect time. Fill with `umbra abuse sync`. Miss is only clean if feeds were synced |
| `opencorporates` | org, person | Company HTML search | Often captcha; prefer `wikidata` |
| `public_records_portals` | org, person | Free **50-state + DC** SOS/courts/SOR + county packs (Benton/Washington AR, Bay CA, San Diego) + national obit indexes + CourtListener/FEC name JSON | Manual search aids; name-token ≠ identity |
| `court_records` | org, person | Federal + state **court opinions and RECAP dockets** from the CourtListener API (Free Law Project, no key) | **API, not scraping.** Candidates at 0.35 with `identity_confirmed: False`. FCRA note on every run. See `docs/RECORDS.md` |
| `county_records` | org, person | Allowlisted **GET** of curated portal pages; store links; parse **land (APN/situs)** and **corp (LLC/Inc)** candidates when the name is on the page | **No login, no PACER, no captcha bypass**. Miss ≠ identity |
| `wifi_maps` | mac, location, person, org | WiGLE / OpenWifiMap / Deflock / WaveDigger **portals**; optional WiGLE BSSID API; OSM Overpass ALPR/cameras; operator Network Survey JSON | **No map-UI scrape**. Last-seen ≠ residence. Randomized MAC skipped |
| `sex_offender_registry` | person | NSOPW + **every state registry homepage**; parse DOB/address/AKA when **first and last** name are on the page | Candidate only. No captcha, no photo dump, no identity claim |
| `animal_registry` | person | Cited **animal-abuse findings** (convictions, pleas, government registry listings, civil orders) from the **owned** registry lake | **Offline**. Evidence only, no new person nodes; exact / first+last matches only (weaker counted, not reported). Charges are never stored; removed, expired, suppressed and disputed rows never surface. Empty lake = unknown, not clean. See `docs/ANIMAL-REGISTRY.md` |
| `inmate_locator` | person | Federal **BOP inmate locator** JSON search — register number, facility, age when **first and last** name match a returned record | **No Chromium.** One documented JSON POST, no captcha bypass, no state DOC scrapers. Candidate only, `identity_confirmed: False`. Portal URL always stored, even on 403/error/captcha. FCRA note on every hit. See `docs/RECORDS.md` |
| `obituary_search` | person | DDG discovery + allowlisted page scrape + **rich parse** (age/dates/places/funeral/kin) + **people lake** upsert (stores every source **link**) | `umbra people status\\|lookup`; weak until confirm |
| `crypto_screen` | crypto_address | OFAC + curated labels from the **owned** crypto lake | **Offline**. Same as `umbra crypto screen` / `/crypto`. Empty lake = unchecked, not clean |

| `rdap_domain` | domain | RDAP registration | No key |
| `rdap_ip` | ip | RDAP network/org | No key |
| `security_txt` | domain | RFC 9116 security.txt contacts | No key |
| `sslbl_cert` | cert | Certificate vs abuse.ch SSL Blacklist from the **owned** lake | **Offline**. Needs SHA-1 on the cert entity (`tls_cert` / `ct_lake`). Fill with `umbra abuse sync`. **Runs on a default domain intent**, not only `umbra playbook` |
| `tech_fingerprint` | domain, url | Local stack fingerprint | BuiltWith substitute |
| `tls_cert` | domain | Live TLS SANs/issuer + **negotiated TLS version / cipher / ALPN** from the same handshake | Sets `fingerprint_sha256` + `fingerprint_sha1`/`sha1` on cert entities. ALPN is offered on the existing ClientHello — **no second handshake, no JARM** |
| `username_presence` | username | Multi-site profile probes | Soft-404 hardened |
| `wayback_cdx` | domain, url | Internet Archive CDX | Apex URLs only for URL inputs |
| `wikidata` | org, person, location | Wikidata claims with per-claim provenance | No key; CC0 |
| `ip_reputation` | ip | Spamhaus ZEN, Feodo, Tor exit, AbuseIPDB | Key-free baseline; optional AbuseIPDB key |
| `domain_reputation` | domain | Spamhaus DBL, OpenPhish (+ optional URLhaus API) | Bulk URLhaus path is `malware_infra`. **Runs on a default domain intent**, not only `/reputation` and `umbra playbook` |
| `ransomware_exposure` | domain, org | Ransomware leak-site exposure via ransomware.live | Key-free, passive/defensive. **Runs on a default domain intent**, not only `umbra playbook` — ordered last so a slow feed cannot starve DNS/TLS |

## Playbook default set

`umbra playbook` runs the curated ordered set in `_PLAYBOOK_COLLECTORS`
(`cli/playbook_cmd.py` — keep both in sync when adding a collector):

`people_lake`, `email_profile`, `email_split`, `dns_resolve`, `dns_email_auth`, `rdap_domain`, `rdap_ip`, `asn_cymru`, `ip_geo`, `http_probe`, `tech_fingerprint`, `html_links`, `tls_cert`, `sslbl_cert`, `ct_lake`, `crtsh`, `security_txt`, `lookalike_domains`, `wayback_cdx`, `github_user`, `mac_oui`, `phone_validate`, `crypto_screen`, `wikidata`, `cve_lookup`, `github_commits`, `username_presence`, `gravatar`, `ddg_search`, `public_records_portals`, `county_records`, `wifi_maps`, `sex_offender_registry`, `animal_registry`, `inmate_locator`, `obituary_search`, `court_records`, `edgar_search`, `opencorporates`, `hibp_breach`, `ip_reputation`, `domain_reputation`, `malware_infra`, `ransomware_exposure`

## Owned GeoIP lake (DB-IP City Lite)

```bash
umbra geoip sync          # download free monthly CSV → local SQLite
umbra geoip status
umbra geoip lookup 8.8.8.8
umbra geoip import-csv ./dbip-city-lite.csv.gz   # air-gap
```

| Item | Detail |
|------|--------|
| Source | [DB-IP IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) (CC-BY 4.0) |
| Path | `$UMBRA_DATA_DIR/lake/geoip.sqlite` or `UMBRA_GEOIP_DB` |
| Collector | `ip_geo` — emits `LOCATION` + `located_in` + IP props (`geo_country`, …) |
| Honesty | Approximate; VPN/CGNAT/anycast skew. Empty lake → *unchecked*, not clean |

Attribution (required by license when redistributing products): **IP Geolocation by DB-IP** — https://db-ip.com


## Owned abuse.ch lake

```bash
umbra abuse sync          # all feeds (GuardedClient egress)
umbra abuse sync -f sslbl # one feed
umbra abuse status
```

| Feed | Read by | Notes |
|------|---------|--------|
| URLhaus bulk CSV | `malware_infra` | Key-free bulk |
| ThreatFox CSV | `malware_infra` | C2 IOCs + family |
| Feodo JSON | `malware_infra` | Botnet C2 IPs |
| SSLBL CSV | `sslbl_cert` | SHA-1 malware C2 certificates |

**MalwareBazaar is not ingested** — keyed by file hash; Umbra graphs do not produce file hashes.

A miss is only clean if the feed was checked (same honesty rule as DNSBL / crt.sh outages).

## Certificate identity notes

- `crtsh` / `ct_lake` name certs by **serial**; `ct_lake` also stores `fingerprint_sha256` + `fingerprint_sha1`.
- `tls_cert` keys the cert entity on SHA-256 and puts both fingerprints in props.

### Server stack fingerprint (`fp_*` props)

`tls_cert` and `http_probe` already make one TLS handshake and one HTTP GET on
an authorized lookup. They used to discard everything about *how* the peer
answered. These props keep it — no new collector, no new port, no new entity
type, **count stays 40**.

| Prop | From | On |
|------|------|----|
| `fp_tls_version`, `fp_tls_cipher`, `fp_alpn`, `fp_http2` | `tls_cert` handshake | DOMAIN, CERT |
| `fp_header_order_sha256` | `http_probe` — sha256 of the first 32 header **names**, lowercased, comma-joined | DOMAIN |
| `fp_server` | `http_probe` — the `Server` header | DOMAIN |
| `fp_favicon_sha256`, `fp_favicon_bytes` | `http_probe` — `{origin}/favicon.ico`, **only** after that origin's HTML already answered | DOMAIN |

Rules that keep it honest:

- **A fingerprint is not an identity.** Every host behind one CDN negotiates
  identically, because to the handshake it *is* the CDN. Shared hosting
  collides the same way. Header order is the weakest of the set and is worth
  no more than 0.4 confidence.
- **A miss is unchecked.** A refused handshake or a 404 favicon writes *no*
  `fp_*` key, rather than a null that renders as a finding. A server that
  negotiates no ALPN gets no `fp_http2`, because silence is not "no HTTP/2".
- **Names, never values.** Header values carry `Set-Cookie` and session ids and
  have no business in a durable fingerprint.
- **Same origin only.** The favicon is fetched from the host that actually
  served the HTML, which after a redirect is not the seed.
- Not implemented on purpose: JARM, extra ClientHellos, SSH banners, extra
  ports, and any form of visitor fingerprinting.

**`tls_cert` now enforces the egress guard.** It opens `socket.create_connection`
directly rather than using `GuardedClient`, so AGENTS.md §2 was not actually
being applied on that path — latent while only authorized CLI and case runs
reached it. `guard_host()` refuses non-public and unresolvable targets before a
packet leaves, and fails closed. That had to land before `/reputation` could
run it, because that page takes its host from an anonymous visitor.

`/reputation` runs `tls_cert` and `http_probe` on **domain** lookups so the
fingerprint block has something to show. The **IP** path stays passive — an IP
has no hostname to offer as SNI, and `http_probe` is deliberately excluded from
`PASSIVE_COLLECTORS` (`tests/test_ip_corpus.py`).

**The page derives its collectors from the planner (2026-09-13).**
`_collectors_for()` used to be a hand-written list per entity type. The IP side
had a discipline that kept it honest — named exclusions with written reasons,
and a test asserting the page equalled `_IP_CORE` minus those names. The domain
side had none: four collectors, with `dns_resolve`, `dns_email_auth`,
`rdap_domain`, `ct_lake`, `sslbl_cert`, `cve_lookup`, `security_txt` and
`tech_fingerprint` absent for no recorded reason. An audit of 1,009 production
cases found 94 domain lookups answered with a verdict and nothing to check it
against.

It now takes `select_collectors()` and subtracts `PUBLIC_EXCLUDED`, a mapping of
name → reason. **The default is to serve**, so a new collector reaches visitors
unless somebody writes down why it should not.
`tests/test_public_collector_parity.py` fails on an undocumented omission.

Currently withheld, all deliberate: `internetdb` (surfacing open ports for any
address a stranger types is a product decision not yet made), `urlscan_io`
(third-party shared quota), `crtsh` (rate-limits and 502s; `ct_lake` answers the
same question offline). Widening the list also gave the page its own wall-clock
budget — `PUBLIC_BUDGET_S`, passed to `Orchestrator.run(max_seconds=...)`, since
`job_max_seconds` is 1800 and this path is synchronous.
- **Tor sources, authoritative first.** The signed **directory-authority
  consensus** is the ground truth the others derive from, and nine servers
  publish it — redundancy against an outage or a hostile middlebox. Fetching
  them on 2026-09-01, two returned an **ISP block page at HTTP 200** (AT&T,
  claiming "malware, phishing"), so a document is only accepted once it
  identifies itself as a consensus. It also carries what the derived feeds drop:
  the **exit policy** (a relay can hold the Exit flag and `reject 1-65535`) and
  `valid-after`, so data age is a fact. Onionoo then adds **exit addresses that
  differ from a relay's OR address** — 22 relays across 10 IPs, and those are
  exactly the addresses that turn up in someone's logs. `dan.me.uk` remains
  available (`--source dan`) but is rate limited and drops its data silently.
- **Tor is a role, not a verdict.** `ip_reputation` reads the owned relay lake
  (`umbra tor sync`, hourly). It used to read `torbulkexitlist`, which is exits
  only — measured 2026-09-01, that is 1,354 of 7,378 running relays, so **82% of
  the consensus produced no answer at all** and the silence read like a clean
  result. Exit and non-exit are reported distinctly: an exit can originate a
  connection to your service, a middle relay cannot. `BadExit` is kept separate
  again, because that is the directory authorities marking a relay as
  misbehaving. None of it moves the score.
- `sslbl_cert` joins on SHA-1 only (SSLBL's key). No SHA-1 → *unchecked*, never *not listed*.
- **A cert is a pivotable entity.** `sslbl_cert`'s only input is `cert`, and
  `cert` was missing from the orchestrator's `_PIVOT_TYPES`, so every
  certificate `tls_cert` and `ct_lake` produced was a dead end. Production on
  2026-09-01 had **2,195 cert entities, 190 `tls_cert` runs and zero
  `sslbl_cert` evidence rows** — naming the collector in a plan without this
  would have been a name that never fires.

## Entity types

`domain`, `ip`, `email`, `url`, `username`, `org`, `person`, `cert`, `asn`, `phone`, `repo`, `technology`, `nameserver`, `registrar`, `breach`, `paste`, `location`, `mac`, `vulnerability`, `malware`

## Edge types (selected)

`resolves_to`, `hosts`, `owns`, `uses_email`, `subdomain_of`, `same_as`, `registered_by`, `issued_for`, `uses_tech`, `member_of`, `has_mx`, `has_ns`, `exposed_in`, `lookalike_of`, `security_contact`, `has_profile`, `associated_with`, `mentions`, `affected_by`, `indicator_of`, …

## Adding a collector

1. Implement `BaseCollector` in `src/umbra/collectors/`.
2. Register in `default_registry()` (`base.py`).
3. Add trust weight in `core/scoring.py` `COLLECTOR_TRUST`.
4. Add its name to `_PLAYBOOK_COLLECTORS` in `cli/playbook_cmd.py` when it belongs in the curated set.
5. Update **this file** and run `pytest`.

## Overpass is slot-limited, not rate-limited

`umbra rf sync` reads OSM surveillance cameras through Overpass. Overpass does
**not** limit requests per second — it grants **slots** per client IP.
`/api/status` reports:

```
Rate limit: 2
2 slots available now.
```

or, when they are gone:

```
Slot available after: 2026-08-30T15:53:46Z, in 47 seconds.
```

Exceed them and you get **429**. Hit a busy server and you get **504**. Both are
transient and both mean *come back shortly*.

The original sync did neither. It fired fourteen regions back to back with a
1.1s pause — a figure tuned for Nominatim's one-request-per-second policy, which
has nothing to do with how Overpass works — and dropped any region that came
back 429 or 504:

```
rf sync ok cameras_upserted=206 fails=4
fail Rogers, AR: overpass 504
fail Berkeley, CA: overpass 429
fail Alameda, CA: overpass 429
fail San Mateo, CA: overpass 429
```

Note the word `ok` on a run that never looked at four cities.

`_overpass_fetch` now waits for a slot before querying, retries 429/502/503/504
with backoff (honouring `Retry-After`), and only after the primary instance has
refused does it fall back to the kumi.systems mirror — politeness order matters,
since that is someone else's capacity. A 400 is never retried: a malformed query
fails identically every time, and hammering a public service with it is rude and
pointless. The server-side `[timeout:60]` now exceeds our HTTP timeout, so we no
longer hang up on a query the server is still running, which was its own way of
manufacturing a 504.

Same fourteen regions after the fix: **14/14 checked, 0 failures.**

### A region that was not checked is not a region with no cameras

The failure that mattered was quieter than the 429s. A rate-limited region left
**no trace in the lake** — no rows, and no record that we had tried. So
`umbra rf cameras Berkeley` printed *"no cameras for 'Berkeley'"*, which is the
same thing it prints for a city that genuinely has none.

`region_sync` records the outcome of every attempt, and the CLI now answers
three different questions three different ways:

| State | What you get |
|---|---|
| never attempted | `never synced — 'X' has not been checked` |
| last attempt failed | `not checked — the last attempt failed (HTTP 429…). This is unknown, not zero.` |
| checked, nothing found | `no cameras mapped near 'X' (checked …) — that is the answer, not a gap` |

`umbra rf status` lists any region whose last attempt failed.

### The cap was hiding data

`out body N` truncates server-side, and N was 25. On the first run that
disclosed it, **seven of fourteen** cities came back at exactly the cap — the
Bay Area packs have far more mapped cameras than that, and the lake had been
storing a fraction of them with no indication. N is now 200, capping is
reported, and the same sync stores **1,256 cameras instead of 206**. Three
cities still exceed 200 within 4 km, and the run says so.
