# Crypto Exploration & Blockchain Intelligence

**Status:** **C1–C4 + C6 shipped** (2026-08-19) · **Web `/crypto` shipped** (2026-08-28)  
**Vault research:** `Documents/CarlsVault/Projects/OSINT/Umbra-Crypto-Exploration.md`  
**Code package:** `src/umbra/crypto/`  
**Ethics:** `docs/ETHICS.md` — lawful, defensive, provenance on every label  

## Surfaces (must match)

| Action | CLI | Web |
|--------|-----|-----|
| Screen one address | `umbra crypto screen ADDRESS` | `POST /crypto/screen` · `GET /v1/crypto?address=` |
| Form / empty lake copy | — | `GET /crypto` |
| Lake stats | `umbra crypto stats` | counts on `/crypto` |
| Case graph | `umbra intent "0x…" --confirm` runs `crypto_screen` collector | same collectors via `/run` |
| Sync OFAC | `umbra crypto labels sync` | CLI/operator only |
| Neighbors / tail | `umbra crypto neighbors` / `tail` | CLI only (v1) |

Intent one-box (`umbra intent` / `/`) extracts unambiguous BTC/ETH/TRON addresses as `crypto_address` seeds and **does not** fall through to DuckDuckGo. Screen those at `/crypto`.

---

## 1. Product intent

Defensive **address screening, bounded fund-flow expansion, and service-touch detection** inside Umbra cases.

| In scope | Out of scope (v1) |
|----------|-------------------|
| Screen vs OFAC SDN + ransomware payment lists | Trading, portfolio, price bots |
| 1–2 hop neighbor graph via public APIs | Self-host Solana archive / multi-TB lakes on app VPS |
| Flag interactions with known mixers/bridges | Monero full-trace “deanonymize” claims |
| Case graph + evidence + confidence | Silent mass wallet surveillance |
| CLI `umbra crypto …` | Replacing Chainalysis |

**Copy rule:** mixer interaction and crowdsourced scam tags are **risk signals**, not determinations of guilt.

---

## 2. Chains & assets (priority)

### Tier 0 (first)

| Rail | Chains | Why |
|------|--------|-----|
| BTC | Bitcoin | Ransom, OFAC XBT, peel chains |
| ETH + ERC-20 | Ethereum | Mixers, DeFi heists, stablecoins |
| USDT / USDC | ETH + **TRON** first | Dominant cash-out |
| TRX | Tron | Cheap TRC-20 volume |

### Tier 1

SOL (+ SPL), BNB Smart Chain (BEP-20), XRP, LTC.

### Tier 2 / special

Monero (labels only), Lightning, other L1s on demand.

**Investigative set ≠ pure mcap**, but 2026 mcap context still puts BTC/ETH/USDT/USDC/SOL/BNB/XRP at the top of global liquidity.

---

## 3. Data model (logical)

### Objects

- **AddressRef** — `(chain_id, address_normalized)`
- **Transfer** — from, to, asset, amount_raw, decimals, txid, index, block_time
- **Label** — tag, source, confidence, url, first_seen, last_seen, raw_ref
- **Service** — kind (`mixer|bridge|exchange|other`), chain, addresses/contracts, name
- **Cluster** (optional) — heuristic id + members (BTC-first)

### Label tags (v1)

```text
sanctioned_ofac
ransomware_payment
theft_proceeds
mixer_service
mixer_user_interaction
bridge
exchange_deposit
scam_reported          # low confidence default
```

### Future graph enums (implementation PR + tests — do not half-wire)

Suggested `EntityType`: `crypto_address`, `crypto_tx`, `crypto_token`, `crypto_service`  
Suggested `EdgeType`: `sent_to`, `received_from`, `interacted_with`, `bridged_via`, `clustered_with`, `labeled_as`

Until then, collectors may store structured props on generic entities **or** wait for enum PR — prefer enum PR with tests.

---

## 4. Storage budget

### Do not self-host on app VPS

| Chain | Full/archive ballpark | Decision |
|-------|----------------------|----------|
| Bitcoin full | ~0.7–0.8 TB class (2025–26) | Optional dedicated node later |
| Ethereum full | ~1–1.5 TB class EL+CL+blobs | RPC/API only |
| Solana archive | **hundreds of TB** | Never on Umbra app host |

### Do store

| Lake | Size target |
|------|-------------|
| OFAC + ransomware + service registry | **&lt; 200 MB** |
| Case-scoped addresses/txs/edges | GBs over years w/ retention |
| API response cache | Redis TTL or small disk LRU |

**Prod growth budget v1:** plan ≤ **5 GB/year** crypto data unless a second volume is added.

---

## 5. Malicious & high-risk sources

| Source | Tag | Notes |
|--------|-----|-------|
| OFAC SDN digital currency IDs | `sanctioned_ofac` | Parse official files; refresh on timer |
| Ransomwhere | `ransomware_payment` | Crowdsourced; intel grade |
| LE/Treasury attributions | `theft_proceeds` | Curated importers |
| Known mixer contracts | `mixer_service` | Registry JSON |
| User↔mixer edges | `mixer_user_interaction` | Behavioral + contract match |
| Chainabuse etc. | `scam_reported` | Optional, low confidence |

### Tornado Cash (and similar)

- Non-custodial pool mixer on Ethereum; historically used in large laundering case studies (incl. DPRK-linked and bridge-hack proceeds per public Treasury materials).
- OFAC designated Tornado Cash **2022-08-08**; later court challenges; **2025** public reporting of **removal from SDN** — **always re-check live SDN** before UI asserts “currently sanctioned.”
- Umbra always records **service interaction** independently of current SDN status.
- Peers/classes: Blender.io (OFAC 2022), other mixers, major bridges post-exploit.

---

## 6. Providers (API-first)

| Provider | Chain | Env |
|----------|-------|-----|
| Esplora / mempool.space | BTC | optional base URL |
| Etherscan API | ETH (+ family) | `UMBRA_ETHERSCAN_API_KEY` |
| TronGrid | TRX/TRC20 | `UMBRA_TRONGRID_API_KEY` |
| Helius / public RPC | SOL | `UMBRA_HELIUS_API_KEY` |
| Alchemy/QuickNode | multi | optional fallback |
| Treasury SDN download | labels | no key |
| Ransomwhere export | labels | no key |

All HTTP via existing `GuardedClient` / httpx guard patterns. Rate-limit and cap pages per job (`UMBRA_CRYPTO_MAX_TRANSFERS`, default 200).

---

## 7. Runtime architecture

```text
seed address
  → normalize (umbra.crypto.normalize)
  → label lake screen
  → provider.transfers (capped)
  → service registry match on counterparties
  → CollectorResult entities/edges/evidence
  → worker job only (no web-loop orch.run)
```

Playbook: `crypto_screen` (labels only) and `crypto_trace` (labels + hops).

CLI (planned):

```bash
umbra crypto screen <addr>
umbra crypto trace <addr> --depth 1
umbra crypto labels sync --source ofac
umbra crypto labels sync --source ransomwhere
```

---

## 8. Package layout (framework)

```text
src/umbra/crypto/
  __init__.py       # public exports
  normalize.py      # parse/normalize addresses
  types.py          # AddressRef, Transfer, Label, ServiceDef
  labels.py         # LabelStore protocol + memory impl
  services.py       # ServiceRegistry
  providers/
    base.py
    null.py         # test double
```

Collectors and CLI land in C1+ slices with registry + tests.

---

## 9. Delivery phases

| ID | Slice | Exit criteria |
|----|-------|---------------|
| **C0** | Design + stub package | ✅ this doc + importable `umbra.crypto` |
| **C1** | OFAC lake + `screen` | ✅ 961 addresses indexed · 29 tests · Ransomwhere deferred (API 502) |
| **C2** | BTC+ETH depth-1 neighbors | ✅ Esplora (BTC) + owned targeted ETH index · no Etherscan, no key |
| **C3** | Mixer/bridge registry edges | ✅ verified registry · service touch · pools in the watch set |
| **C4** | TRON USDT | ✅ TronGrid, key-free · token impersonation defended |
| **C5** | SOL/BSC adapters | broader coverage |
| **C6** | Address watch jobs | ✅ labelled-address movement alerts via the ops path |
| **C7** | Optional heavy analytics host | explicit infra approval |

---

## 10. Tests (required per slice)

- Address normalize vectors (BTC bech32/base58, ETH checksum, TRON)
- OFAC fixture → label hit / miss
- Cap enforcement (max transfers)
- Service touch on known pool address fixture
- No network in unit tests (provider fakes)

---

## 11. Non-goals / pitfalls

- Do not add `EntityType` values without registry + COLLECTORS + tests same PR  
- Do not treat delisted mixer contracts as “still OFAC” without live list  
- Do not run unbounded BFS on popular exchange hot wallets  
- Do not put explorer API keys in the public OSS extract without docs  
- DNSBL rules unrelated; crypto egress still uses GuardedClient  

---

## Related

- `docs/ETHICS.md` · `docs/OPEN-CORE.md` · `docs/PHASES.md` · `docs/COLLECTORS.md`  
- Vault: `Projects/OSINT/Umbra-Crypto-Exploration.md`

---

## C1 — shipped 2026-08-19

`umbra crypto labels sync` reconciles the OFAC SDN file into the lake;
`umbra crypto screen <addr>` answers from it with **no network call**. Same
"own the data" pattern as the CT corpus, the OUI table and abuse.ch.

### What is actually in there

Measured on the live file, not estimated:

| | |
|--|--|
| SDN.XML | 28 MB, via a redirect to a presigned S3 URL — callers must follow redirects |
| Digital currency addresses | **977** across 13 asset codes, on 94 sanctioned entities |
| Indexed after dedupe | **961** — the file lists some addresses under more than one entry |
| Top chains | btc 531 · tron 277 · eth 104 · ltc 13 · xmr 11 |
| Cost | free, no key |

### Three decisions the design doc did not settle

**A sync is a reconciliation, not an append.** The doc names the trap — *"do not
treat delisted mixer contracts as still OFAC"* — and this is the mechanism that
avoids it. Every address in the new file is active; every address absent from it
is **delisted with a date**; nothing is deleted. Tornado Cash was designated in
2022 and removed in 2025, and an address Umbra keeps labelling
`sanctioned_ofac` after removal is a false accusation of sanctions evasion, not
a stale cache entry. `screen` reports former listings separately: *"formerly
sanctioned_ofac, delisted YYYY-MM-DD — historic listing only."*

**An empty snapshot is refused by default.** A fetch that failed and a genuine
mass delisting look identical from the parser's side, and only one of them
should clear every sanctions label. `replace_source(..., allow_empty=True)` is
the explicit override.

**The asset code is not the chain.** OFAC writes `Digital Currency Address -
USDT`, which may be ERC-20 or TRC-20; the chain comes from the address format,
with the OFAC code kept as provenance. Monero and Zcash addresses match none of
the format patterns, so they fall back to a code→chain map rather than being
dropped — silently losing sanctioned addresses to a regex would be the worst
possible failure here.

### Labels name a party, not just a string

Every row carries the SDN entity, its uid and its programmes, so the claim is
checkable against the same public file anyone can download:

```
12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h  chain=btc
  sanctioned_ofac (source=ofac_sdn, confidence=0.98)
    OFAC SDN listing: Xiaobing YAN (SDNTK)
    https://sanctionslist.ofac.treas.gov/Home/SdnList
```

A miss says so honestly: *"not on any list Umbra has indexed (961 addresses).
Absence from these lists is not proof the address is clean."* An unsynced lake
says **not checked**, never clean.

### Ransomwhere is deferred, not skipped

`api.ransomwhe.re/export` returned **502 on every attempt**. It stays in the
design as a C1.5 source; the lake is already multi-source and per-source
reconciliation means adding it later cannot disturb the OFAC entries.

---

## C2 — shipped 2026-08-19, without Etherscan

Carl's constraint: **do not depend on Etherscan; build something better.** What
"better" can honestly mean was decided by measuring the alternatives first.

### What free infrastructure actually allows

| | Bitcoin (Esplora) | Ethereum (public JSON-RPC) |
|--|--|--|
| Full address history | ✅ | ❌ |
| `eth_getLogs` without a contract address | n/a | refused |
| Reads past ~64 blocks | n/a | *"archive requests require a personal token"* |
| Key required | none | none, within the window |
| Independent operators | mempool.space, blockstream.info | one of five probed answered cleanly |
| Self-hostable later | ✅ same software, own node | ✅ own node |

**Bitcoin is solved.** Esplora is an open backend with two independent public
instances and no key, and — the part that matters — it is the *same software*
Umbra can run against its own full node later. The API contract does not change
when the backend becomes ours. Failover is across operators, not retries.

**Ethereum cannot be out-archived.** Free RPC is roughly **fifteen minutes** of
history. No amount of engineering turns that into Etherscan's archive, and
pretending otherwise would ship the worst possible thing: a screen that looks
complete and is not.

### So "better" means something specific

Umbra follows the chain head and keeps **only transfers touching an address it
already cares about** — the OFAC label set, case addresses, the watch list.
Measured live: 20 blocks carried **3,780** USDT/USDC transfer logs and stored
**0**, because none of the 104 watched ETH addresses moved in that window.

That is worse than Etherscan at "show me this address's whole history" and
better at the things that matter here:

| | Etherscan | Umbra's index |
|--|--|--|
| Who learns which addresses you investigate | Etherscan does | **nobody** |
| "Alert me when any of these 961 addresses moves" | cannot be asked | the design |
| Provenance | trust the explorer | re-derivable from owned rows |
| Rate limits / keys | yes | none |
| Full historical archive | ✅ | ❌ tail-forward, and says so |

The query-privacy point is not incidental for an OSINT tool: every explorer
lookup tells the explorer who you are interested in.

### Why targeted, not exhaustive

USDT alone is ~1.36M transfers/day (measured: 3,780 logs in 20 blocks). Indexing
one token would be ~47 GB/year against the 5 GB/year budget in §4. Targeting is
what makes the arithmetic work **and** what makes the index worth having rather
than a worse copy of a public database.

### Operational shape

| Timer | Cadence | Why that cadence |
|---|---|---|
| `umbra-crypto-tail` | **10 min** | free RPC refuses reads past ~64 blocks (~13 min); a longer gap is history that cannot be recovered without a paid archive |
| `umbra-crypto-labels` | daily | a delisting Umbra has not picked up is a false sanctions accusation left standing |

```bash
umbra crypto neighbors <btc-address>   # depth-1 counterparties, labelled
umbra crypto tail --blocks 48          # one head-follow tick
```

### Honest limits

- **Native ETH transfers are not indexed** — they need `trace_*`, which free
  endpoints do not expose. ERC-20 covers the stablecoin rails §2 calls dominant.
- **The ETH index starts empty** and grows forward. It answers "has this watched
  address moved since we started watching", never "what did it do in 2022".
- **Bitcoin transfer direction is an interpretation.** Many inputs, many outputs
  — change is dropped rather than counted as a self-payment, and unrelated
  outputs in a transaction that merely paid you are not counterparties.
- A dead Esplora instance yields **not checked**, never "no transactions".

---

## C3 — the service registry, shipped 2026-08-19

The most defamation-adjacent thing in the module, so it has two hard rules.

### Nothing enters on recollection

Every entry carries a `verification` block. The shipped Tornado Cash pools were
checked with `eth_getCode` against a public node before anything was written to
a file:

| Address | Code | sha256 |
|---|---|---|
| `0x12d6…b8fc` (0.1 ETH) | 6,615 bytes | `3bbc2652c41f0a13` |
| `0x47ce…2936` (1 ETH) | 5,191 bytes | `57632dbb86b78ae0` |
| `0x910c…9dbf` (10 ETH) | 5,191 bytes | `57632dbb86b78ae0` |
| `0xa160…f291` (100 ETH) | 5,191 bytes | `57632dbb86b78ae0` |

Three share **byte-identical bytecode**, which is what one contract deployed at
several denominations looks like — corroboration rather than assertion. A fifth
candidate address turned out to have **no code at all** and was dropped instead
of shipped. An address labelled "mixer" that is not one is a false accusation
against whoever controls it.

### The registry never claims sanctions

`sanctions_status` is deliberately not a field, and a test enforces that the
word does not appear in an entry. Only the live SDN lake answers that question.
The proof it matters, from the shipped system:

```
umbra crypto screen 0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936
  mixer: Tornado Cash (ETH pool, 1 ETH)
  no active labels — not on any list Umbra has indexed (961 addresses)
```

Correctly identified as a mixer, correctly **not** reported as sanctioned —
Tornado Cash was designated in 2022 and removed in 2025. A static "sanctioned"
list would have been wrong here, about a real party, in the accusing direction.

### Interaction is a signal

`service_touches()` flags counterparties that are known services, and the CLI
says plainly:

> Service interaction noted. Using a mixer or bridge is not a crime and is not
> evidence of one — people use privacy tools for private reasons.

### Pools join the head-follower's watch set

C2's targeted index keeps transfers touching addresses of interest, and mixer
contracts are exactly that. A deposit into a pool is caught **as it happens**,
rather than discovered later by asking an explorer — which would also tell the
explorer what is being investigated.

Labels that lapse stop being watched; registry contracts do not, because they
are infrastructure rather than a listing that can expire.

---

## C4 — TRON, shipped 2026-08-19

TRON matters here more than its market cap suggests: **277 of the 961
sanctioned addresses** in the OFAC lake are TRON, second only to Bitcoin, and §2
names TRC-20 USDT the dominant cash-out rail. TronGrid serves address history
**key-free**; a key only raises the rate limit.

### The hazard is impersonation, and it was measured

A TRC-20 contract reports its own name, symbol and decimals. Anyone can deploy
one calling itself USDT. Sampling eight sanctioned addresses from our own lake —
83 transfers:

| Contract | Claims to be | Count |
|---|---|---|
| `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | USDT | **77** |
| `TJXUL2YGcoVaNpFpNrQ9FjeE5AVMMSk6UJ` | `TG: jieuu` | 3 |
| `THxYWbzAgzQgQaYi9G4mjeL1tq1hdrZe55` | `ha138 com` | 2 |
| `TNVd8VBGWUjhHy1dtcmmwuXmBVyy6MUW16` | `unfreeze` | 1 |

**Seven percent is dust-spam wearing a deceptive name** — the address-poisoning
pattern. That sample also confirmed the canonical USDT contract empirically
rather than from memory: 77 of 83 across eight independent addresses.

### So the symbol is never taken on trust

The claimed symbol is shown as fact **only** when the contract is on the
verified list. Everything else renders as the contract with the symbol marked
unverified, and what it *claimed* is kept — a fake USDT arriving at a sanctioned
address is itself a finding.

From the shipped command, against a real sanctioned address:

```
in   TUZPztRsZQMUJVXQYKwE…   302676   unverified TJXUL2YGcoVa…
in   TAg7Tc5tQT8F2igqtfsN…    64237   USDT
2 transfer(s) came from unverified token contracts.
```

A naive reading of `token_info.symbol` would have printed **302,676 USDT** —
six figures of fake money at a sanctioned address, presented as real. Same rule
as C1's "the asset code is not the chain": provenance decides, never a label
somebody else controls.

### Wiring

`umbra crypto neighbors` is chain-aware — Bitcoin via Esplora, TRON via
TronGrid, both key-free, both capped, both reporting **not checked** rather than
"no transfers" when every instance refuses.

---

## C6 — alerts, shipped 2026-08-19

C2 built the head-follower and C3 filled its watch set. Until now the whole
thing recorded quietly and woke nobody. C6 wires it to `record_ops_event`, so
alerts inherit the existing dedupe, escalation and Telegram path rather than
inventing a second notification channel.

### The watch set and the alert set are different

This is the design, not an implementation detail.

| | Watched (recorded) | Alerted (pushed) |
|---|---|---|
| OFAC-labelled address moves | ✅ | ✅ |
| Labelled address → mixer | ✅ | ✅ **S2**, the loudest thing here |
| Stranger deposits into a mixer | ✅ | ❌ |
| Two unwatched parties | ❌ | ❌ |

Mixer pools are watched so deposits are *recorded* as they happen — but a pool
receives deposits constantly, and paging on each would produce exactly the muted
channel the ops digest was rebuilt to prevent. **A stranger using a mixer is
Tuesday.** A labelled address moving is rare, and is what an investigator wants
pushed rather than polled.

A service on either end raises severity; it never triggers an alert by itself.

### It cannot become noise

- **Fingerprinted per transfer**, not per address — fingerprinting on the
  address would collapse a week of movement into one row nobody looks at twice.
- **Only newly stored transfers alert.** The published window overlaps every
  tick, and re-alerting a replayed transfer is how a channel gets muted.
- **Bursts are capped at 10** with a summary row saying how many were
  suppressed. A hot address could produce hundreds in one tick, and paging
  someone three hundred times is the same as not paging them. A silent cap would
  read as "that was all of it".
- **A delisted label stops alerting.** Alerting because an address *used* to be
  sanctioned is surveillance without a reason.

### Verified end to end

A synthetic transfer for a real sanctioned address from the lake, routed into a
Tornado pool, produced an `S2 crypto_watch_hit` on the live ops surface
alongside the existing job alerts — then was removed, since it never happened.

### Seeing it

```bash
umbra crypto activity            # what the index has recorded
umbra crypto activity <address>  # for one address
```

Empty is reported honestly: *the index is tail-forward and starts empty. It
answers "has this moved since we started watching", never "what did it do in
2022"* — with the block it is following from.
