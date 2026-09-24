# Triage: a tier-1 call on an alert

**Status:** shipped in the CLI (open core) · **Code:** `src/umbra/triage/` · `umbra triage`
**Model:** TypeSafe's Jev, **bring your own key** · **Ethics:** `docs/ETHICS.md`

Umbra investigates, Jev makes the call, and a person decides.

```bash
umbra triage 185.220.101.1
umbra triage suspicious-url.txt
umbra triage alert.json                          # one alert, a list, or NDJSON
siem-export | umbra triage - --json --exit-code  # 0 suggest-close · 10 needs analyst · 20 escalate
```

Every alert gets one of three answers:

| Answer | Meaning |
|--|--|
| **escalate** | A listing, planted instructions, or Jev reads it as attacker infrastructure. A person should act. |
| **needs analyst** | Anything in between. This is where most indicators land. |
| **suggest close** | Every guard agreed it's benign. **A person still closes it. Umbra never does.** |

## Bring your own key

The CLI never uses Umbra's hosted key. Jev runs on yours:

```bash
export UMBRA_OPENROUTER_API_KEY=sk-or-...        # https://openrouter.ai/keys (default provider)
# or
export UMBRA_JEV_PROVIDER=typesafe UMBRA_TYPESAFE_API_KEY=...
```

Setting the key is the opt-in for this command. `UMBRA_JEV_ENABLED` only governs automatic adjudication elsewhere.
**Without a key, triage still runs** on Umbra's deterministic checks and says so. In that mode an unlisted indicator is never suggested for closing, because "no blocklist has it yet" is how most new infrastructure looks.

Cost is small: about $0.00004 per Jev request. Each indicator takes one request, or two when the alert carries text from the far side (see below). Umbra's daily token budget (`UMBRA_JEV_DAILY_TOKEN_BUDGET`) and answer cache apply.

## What it accepts

- **One indicator:** a public IP, domain or URL. A URL also brings its host, because blocklists key on hosts.
- **A JSON alert** in common field names: Elastic ECS, Suricata EVE, Wazuh, Zeek, or flat `src_ip`/`dst_ip`. A list, NDJSON, or an Elasticsearch `hits` response also works. Up to 50 alerts per run.
- **Plain text:** an IOC list or a pasted log line, run through the same deterministic extractor as `umbra file`.

For each alert, Umbra works out the kind (outbound connection, DNS query, web request, inbound connection) and which side is external. On an **inbound** alert, the host name and URL belong to *you*, so only the connecting address is assessed.

## What leaves the machine

Only **public** addresses, domains and URLs are enriched or sent to Jev. **Internal addresses, host names, user names, command lines and file paths are never read into the alert.** The card lists which of those fields were present ("kept local") by name only. `--dry-run` prints the exact state Jev would receive and sends nothing.

Jev also never sees the **blocklist listing**. Listings are decided in code (below), and the thresholds were fitted without them.

## How the call is made

1. **Enrich:** a depth-0 Umbra run on a case recorded with your `--basis` (default `own_asset`). This uses passive collectors only: registries, ASN, DNS, DNSBLs, Certificate Transparency and the owned abuse.ch lake. **Collectors that connect to the indicator are off**: `http_probe`, `tls_cert`, `tech_fingerprint`, `security_txt`, `html_links`. Probing a suspected C2 from your own machine tips off its operator and puts your address in their logs. Use `--active` to turn them back on. `--no-collect` skips enrichment altogether.
2. **Ask:** Jev answers four narrow questions (`soc_triage@1`): the host's role, P(malware or C2), P(ordinary business traffic), and urgency. It never gets "is this malicious?". In testing, that one broad question closed 14% of real threats.
3. **Dual ask:** when the alert carries text the far side controls (user agent, request path, subject), Jev is asked twice: once without that text, and once with it inside a fence plus a canary question. The text **can add suspicion but never remove it**:
   - If it lowers P(malicious) by more than 0.25, the facts-only answer is used.
   - If the canary fires, the alert escalates.
4. **Decide** (`umbra.triage.disposition.decide`, pure, truth-table tested):

| Condition | Result |
|--|--|
| Listed by a blocklist, or the exact host/URL is in the owned URLhaus/ThreatFox/Feodo lake | escalate |
| Canary fired, or the far side's text argued the model toward benign | escalate |
| Jev: malicious role, or P(malicious) ≥ **0.465** | escalate |
| Blocklist check ran clean, enriched, not a critical asset, benign role, P(malicious) ≤ **0.115** | suggest close |
| Anything else, including no key, Jev unavailable, or a partial listing | needs analyst |

Shared platforms (GitHub, CDNs, file hosts) are not treated as listed because a stranger uploaded malware to them. That's the same rule as `docs/SCORING.md`. The upload count reaches Jev as a fact. An exact malicious URL on the platform is still a listing.

`--asset critical` blocks suggest-close for that run.

## Where the thresholds come from

They were fitted on 1,844 labelled alerts: abuse.ch C2/payload/URL indicators, top-site domains, IPs and URLs, and real scanners hitting a public site. Listings were withheld, thresholds were fitted on one half, and results were measured on the other:

| On the held-out half | |
|--|--|
| Real threats suggested for closing | **0 / 385** |
| Threats escalated by Jev alone | 43% (URLs 95%, bare IPs and domains about 18%) |
| Benign alerts suggested for closing | 32% |
| Planted "this is safe" notes that changed a verdict | 0 / 150 (the canary caught 150 / 150) |

The fit is for `typesafe/jev-1.13-20260917`. The card warns when Jev answers from a different build. Treat these as starting points, not guarantees: the positives were *listed* indicators with the listing hidden, and truly new infrastructure may look cleaner.

## Honest limits

- **Umbra sees indicators, not behaviour.** It knows who an address or domain belongs to and whether it's listed. It does not know what a process did on the endpoint. Endpoint and identity alerts go to a person.
- **Bare IPs are the weak case.** With only operator, country and port to go on, Jev can't separate a C2 on a cloud VPS from a CDN edge. Those go to an analyst, which is safe but not much help.
- **An owned lake is only as current as its last sync.** Run `umbra abuse sync` first. The card says when the local lake has never synced, because a known C2 then reads as unlisted.
- **Suggest-close is a suggestion.** It exists to sort a queue, not to empty one.
