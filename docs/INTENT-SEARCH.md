# Umbra Intent Search — AI-powered intake

**Status:** Core implemented — `umbra intent` works (rule-based extraction, 13 passing tests), wired into the web UI (`/search`, `/run`). The optional LLM planner (`UMBRA_LLM_ENABLED=true` / `--llm`) is off by default and less exercised than the rule-based path.  
**Problem:** Field-by-field “username / last name / domain” search is brittle and high-friction. Operators already think in messy notes.  
**Solution:** One **Intent** box. An agent turns natural language into **structured seeds + a collection plan**, then (only after confirm + authorization) runs Umbra workers.

**Entity types the one-box extracts (CLI `umbra intent` = web `/search`):**

domain · IP · email · URL · username · org · person (`person: Full Name`) · phone · MAC · **crypto_address** (BTC/ETH/TRON)

Dedicated lake lookups (same as CLI, no confirm step): `/people`, `/crypto`, `/reputation`, `/phone`.

---

## 1. Product experience

```text
┌─────────────────────────────────────────────────────────────┐
│  Intent                                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ Own brand example-brand.com, GH example-user,        ││
│  │ email hello@…, Bentonville AR, possible handle           ││
│  │ "examplebrand" on IG. Check lookalikes + breaches.       ││
│  └─────────────────────────────────────────────────────────┘│
│  Authorization basis: [ own_asset ▼ ]  Note: [ … ]         │
│  [ Analyze intent ]                                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Plan preview (editable)                                     │
│  Case name: Self-Footprint Example                            │
│  Seeds:                                                      │
│   • domain  example-brand.com     conf 0.95  [x]           │
│   • username github:example-user conf 0.90  [x]           │
│   • email   hello@…                conf 0.90  [x]           │
│   • username instagram:examplebrand conf 0.55  [x] uncertain │
│   • person  Carl Sullivan          conf 0.70  [ ] optional  │
│  Collectors: person_footprint + lookalike + hibp + …       │
│  Depth: 1    Max entities: 500                               │
│  Warnings: IG handle low confidence — verify before pivot  │
│  [ Edit seeds ]  [ Run in cloud ]  [ Save draft ]            │
└─────────────────────────────────────────────────────────────┘
```

**Critical UX rule:** LLM never silently starts scraping.  
**Analyze → human confirms → enqueue job.**

---

## 2. Why not “chat that scrapes”

| Bad | Good |
|-----|------|
| Chat blindly calls collectors | Structured **Intent → Plan → Run** |
| Model invents emails/phones | Extract only what’s in text or clearly implied |
| One-shot “dox this person” | Requires **authorization basis** + audit |
| Unbounded pivots | Depth/budget + verification gates |

The agent is a **compiler** from messy language → Umbra’s existing graph engine — not a replacement for collectors.

---

## 3. Architecture

```text
                    ┌──────────────┐
  Intent text  ───► │ Intent API   │
  + basis/note      │ POST /intent │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │  Planner agent           │
              │  1. Normalize / PII tag  │
              │  2. LLM structured out  │
              │  3. Schema validate      │
              │  4. Deterministic fixups │
              │  5. Collector selection  │
              └────────────┬────────────┘
                           │ IntentPlan JSON
              ┌────────────▼────────────┐
              │  UI / CLI preview        │
              │  user edits + confirms   │
              └────────────┬────────────┘
                           │ POST /cases/{id}/runs
              ┌────────────▼────────────┐
              │  Worker (existing)       │
              │  Orchestrator+collectors │
              │  score → profile         │
              └──────────────────────────┘
```

### Components

| Component | Role |
|-----------|------|
| **Intent API** | Accept free text + basis; return `IntentPlan` |
| **Planner** | LLM + validators + rule-based extractors |
| **Plan schema** | Versioned JSON (seeds, collectors, depth, warnings) |
| **Run confirm** | Creates case/seeds, enqueues worker job |
| **Optional chat** | Follow-ups only refine the **plan**, not live scrape mid-sentence |

---

## 4. IntentPlan schema (contract)

```json
{
  "schema_version": 1,
  "case_name": "Self-Footprint Example",
  "authorization_basis": "own_asset",
  "authorization_note": "Personal brand inventory",
  "summary": "Brand domain + GitHub + email; lookalikes and breaches.",
  "seeds": [
    {
      "type": "domain",
      "value": "example-brand.com",
      "confidence": 0.95,
      "source_span": "example-brand.com",
      "include": true,
      "notes": null
    },
    {
      "type": "username",
      "value": "github:example-user",
      "confidence": 0.9,
      "source_span": "GH example-user",
      "include": true,
      "notes": null
    }
  ],
  "playbook": "person_footprint",
  "collectors": ["email_split", "dns_resolve", "github_commits", "lookalike_domains", "hibp_breach"],
  "depth": 1,
  "max_entities": 500,
  "flags": {
    "want_lookalikes": true,
    "want_breaches": true,
    "want_corp_records": false,
    "aggressive_username_probe": false
  },
  "warnings": [
    "instagram:examplebrand is inferred — low confidence"
  ],
  "clarifying_questions": [],
  "refuse": false,
  "refuse_reason": null
}
```

### Entity types the planner may emit
Reuse Umbra types: `domain`, `email`, `username` (`platform:handle`), `person`, `org`, `url`, `ip`, `phone` (gated), `location` (as person/org props, not always a seed).

### Confidence bands for seeds
| Score | Meaning | Default include |
|------:|---------|-----------------|
| ≥ 0.85 | Explicit in text | yes |
| 0.55–0.84 | Strongly implied | yes, flagged |
| &lt; 0.55 | Guess | **no** (user must opt in) |

---

## 5. Hybrid extraction (don’t trust LLM alone)

Run **deterministic extractors first**, then LLM for residual semantics.

### 5.1 Deterministic (always)
- Emails: regex  
- Domains/URLs: regex + public suffix awareness  
- IPs: v4/v6  
- `github.com/x`, `x.com/x`, `linkedin.com/in/x` → usernames  
- Phone: libphonenumber (optional, high caution)  
- Hashed-looking strings: skip or treat as unknown  

### 5.2 LLM structured fill
Input = original text + deterministic hits.  
Output = JSON matching schema (function-calling / JSON mode).

**System policy (prompt law):**
1. Only extract identifiers supported by evidence in the text.  
2. Never invent SSNs, full addresses, or employers not stated.  
3. If request is clearly non-authorized harassment/dox of a private third party with no basis → `refuse: true`.  
4. Prefer `username` with platform prefix.  
5. Map vague asks (“check if hacked”) → `want_breaches: true` + email seeds only if present.  
6. Map “brand abuse / typosquat” → `want_lookalikes: true`.

### 5.3 Deterministic post-pass
- Normalize with existing `umbra.core.normalize`  
- Drop invalid seeds  
- Dedup  
- Select collectors from **flags + seed types** (table-driven, not free-form LLM list alone)  
- Cap depth (default 1, max 2 without elevated flag)

### Collector selection table (examples)

| Signal | Collectors added |
|--------|------------------|
| any domain | dns_*, rdap_domain, http_probe, tls_cert, crtsh, security_txt |
| want_lookalikes | lookalike_domains |
| email | email_split, gravatar, hibp_breach (if key) |
| github username | github_user, github_commits |
| any username | username_presence (if flag or explicit) |
| person + location props | public_records_portals, ddg_search (soft) |
| org | wikidata_search, edgar_search |
| want_breaches | hibp_breach |

LLM may *suggest* playbook name; **server maps flags → collectors**.

---

## 6. Model hosting options

| Option | Fit |
|--------|-----|
| **LocalAI on homelab** (you already run it) | Best privacy; free; good for structured JSON if model is strong enough |
| **Cloud LLM API** (Claude/OpenAI/etc.) | Best extraction quality; secrets in worker/API only |
| **Small local + cloud fallback** | Cheap path: regex first; cloud only if text is messy |

**Deployment placement:** Planner runs on **API** (short, CPU/GPU) — not on scrape workers.  
Scrape workers stay dumb executors of confirmed plans.

Config:
```bash
UMBRA_LLM_BASE_URL=http://localai:8080/v1   # or cloud
UMBRA_LLM_MODEL=...
UMBRA_LLM_API_KEY=...                       # if needed
UMBRA_INTENT_REQUIRE_CONFIRM=true           # default true
```

---

## 7. API sketch

### `POST /v1/intent/analyze`
```json
{
  "text": "…",
  "authorization_basis": "own_asset",
  "authorization_note": "…",
  "hints": { "default_depth": 1 }
}
```
→ `IntentPlan` + `plan_id` (stored draft, TTL 24h)

### `POST /v1/intent/plans/{plan_id}/confirm`
```json
{
  "seeds": [/* optional overrides */],
  "collectors": [/* optional */],
  "depth": 1
}
```
→ `{ "case_id", "job_id" }`

### `GET /v1/jobs/{job_id}`
→ status, logs tail, entity counts

### CLI (same brain)
```bash
umbra intent "domain X, github Y, check breaches" -b own_asset --note "..."
umbra intent --file notes.txt -b client_engagement --confirm  # after preview
```

---

## 8. UI: one box, not a form jungle

**Primary:** Intent textarea (large)  
**Secondary (collapsed):** Advanced — depth, collector multiselect, max entities  
**Always visible:** Authorization basis (required)  
**After analyze:** Editable chip list of seeds (toggle include, edit value, set verify later)

Search results page = existing case profile + graph + confidence bands — not a separate “people search engine” SERP that implies unlimited third-party lookup.

---

## 9. Safety & abuse

| Control | Implementation |
|---------|----------------|
| Authorization basis | Required before confirm |
| Confirm gate | No collectors until confirm |
| Refuse class | Harassment/dox patterns without client/own basis |
| Seed confidence | Low-confidence excluded by default |
| Rate limit | N analyzes/hour; N runs/day per user |
| Audit | Store raw intent text + plan JSON + user edits on case |
| SSRF | Unchanged collector HTTP rules |
| PII retention | Intent drafts expire; case data per retention policy |

**Prompt + classifier:** lightweight regex/LLM check for “find my ex”, “her address”, etc. when basis is missing or `training_lab` with third-party focus → refuse or force basis upgrade.

---

## 10. Example transforms

### Input
> Our company example.com, also www.example.org. CEO may use jsmith on GitHub. Need typosquat watch and any breaches on security@example.com.

### Plan (abridged)
- Seeds: `example.com`, `example.org`, `email:security@example.com`, `username:github:jsmith` (0.6, flagged)
- Flags: lookalikes=true, breaches=true  
- Collectors: domain stack + lookalike + hibp + github_*  
- Warning: GitHub handle uncertain  

### Input
> what’s the home address of [private person] in Bentonville

### Plan
- `refuse: true` unless `client_engagement` / lawful basis with note  
- clarifying_question: “Umbra is for authorized asset/CTI use. Provide engagement basis or own-asset scope.”

---

## Implementation status

### Phase I — **done** (deterministic)
- Package: `src/umbra/intent/` (`schema`, `extract`, `plan`)
- CLI: `umbra intent "…" -b own_asset`
- Dry-run by default; `--confirm` creates case + runs collectors
- `--json` / `-o plan.json` for UI/API handoff later
- Tests: `tests/test_intent.py`

```bash
umbra intent "domain example.com, gh octocat, security@example.com, check breaches and lookalikes" -b own_asset
umbra intent --file notes.txt -b client_engagement --note "engagement 123" -o /tmp/plan.json
umbra intent "…" -b own_asset --confirm   # execute
```

### Phase II — **done** (LLM planner)
- OpenAI-compatible client: LocalAI, OpenAI, vLLM, etc.
- `src/umbra/intent/llm.py` + `merge.py`
- Deterministic hits always run first; LLM **adds/merges** (never replaces silently)
- Collectors still mapped **server-side** from seeds/flags
- Fail-soft: LLM errors → deterministic plan + warning

```bash
# Configure (LocalAI example)
export UMBRA_LLM_BASE_URL=http://127.0.0.1:8080/v1
export UMBRA_LLM_MODEL=gpt-4o-mini          # or your LocalAI model id
export UMBRA_LLM_API_KEY=                   # optional
export UMBRA_LLM_ENABLED=true               # auto-use on intent

# Or force per call
umbra intent "messy notes about Acme and their github…" -b client_engagement --llm
umbra intent "example.com only" --no-llm
```

Env vars:

| Variable | Meaning |
|----------|---------|
| `UMBRA_LLM_BASE_URL` | e.g. `http://127.0.0.1:8080/v1` |
| `UMBRA_LLM_MODEL` | Model id |
| `UMBRA_LLM_API_KEY` | Bearer token if required |
| `UMBRA_LLM_ENABLED` | `true` to auto-enrich without `--llm` |
| `UMBRA_LLM_TIMEOUT_S` | Default 60 |
| `UMBRA_LLM_TEMPERATURE` | Default 0.1 |

### Phase III — **done** (basic UI)
- `umbra ui` → http://127.0.0.1:8787/
- Logo, large intent textarea, Search + Guide
- Guide includes dorks and advanced CLI
- Confirm run from results page

### Phase IV — multi-turn + cloud hardening (next)

---

## 12. Relation to deployment

From [DEPLOYMENT.md](DEPLOYMENT.md):

| Service | Runs intent? |
|---------|----------------|
| **API** | Yes — analyze + confirm |
| **Worker** | No LLM required — executes plan |
| **UI** | Intent box + plan editor |
| **Homelab LocalAI** | Optional planner backend via private network |
| **Cloud LLM** | Optional if LocalAI too weak for JSON |

Intent search does **not** change the worker scrape architecture; it only improves how runs are *specified*.

---

## 13. Success metrics

- Time-to-first-run &lt; 60s from messy notes  
- ≥ 90% of auto-seeds accepted without edit on happy-path fixtures  
- 0 collector invocations without confirm (invariant test)  
- Refusal rate appropriate on abuse fixtures  

---

## 14. Naming inside the product

| User-facing | Internal |
|-------------|----------|
| **Intent** | `intent` |
| **Plan** | `IntentPlan` |
| **Analyze** | planner pipeline |
| **Run** | existing orchestrator job |

Optional brand line: **“Cast into the Umbra”** — paste what you know; we shape the shadow.

---

## 15. Next concrete build

Start **Phase I** in-repo:
1. `src/umbra/intent/schema.py` — pydantic plan  
2. `src/umbra/intent/extract.py` — regex/URL extractors  
3. `src/umbra/intent/plan.py` — collectors from flags  
4. `umbra intent "..."` CLI dry-run  
5. Fixtures in `tests/test_intent.py`  

Then wire LLM in Phase II without changing the schema.


## Bare names and corporate suffixes (2026-08-16)

Two extraction rules were added after the E2 `intent_empty` signal caught the
gap: typing `Cloudflare` into the one box produced **no seeds at all**, because
`_ORG_HINT_RE` needed a keyword ("company Cloudflare") and `_PERSON_RE` needed
two capitalized tokens.

- **Corporate suffix** — `Acme Inc`, `Siemens AG`, `Barclays PLC` seed an org at
  0.8 wherever they appear, including mid-sentence. A legal suffix is
  unambiguous.
- **Bare query** — if the whole input is **three words or fewer** and *nothing
  else matched*, it seeds an org at **0.55**, which is exactly the include
  threshold, with the note "assumed from a bare query — uncheck if wrong".

The narrowness is the point. Firing only when the query *is* the name means
"Check this domain for me" cannot become a case about a company called Check,
and a query containing a domain or email is never also guessed at. A stop-list
covers the phrases that would otherwise slip through ("find everything",
"please help me").

0.55 rather than 0.5 is deliberate: below the threshold the seed renders
unchecked, and the plan would have nothing selected — which is the behaviour
this replaced.
