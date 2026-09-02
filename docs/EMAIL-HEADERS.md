# Email header analysis

**Status:** shipped (2026-08-20) — parser, verdicts, plan, CLI, web upload  
**Code:** `src/umbra/email/` · `src/umbra/ingest/` · `umbra email` / `umbra file` · `POST /ingest`  
**Ethics:** `docs/ETHICS.md` · passive, defensive, provenance on every claim

---

## Operator quick start

```bash
umbra email message.eml                  # plan + verdicts, no collectors
umbra email message.eml --confirm        # create case and run
umbra file iocs.txt                      # IPs/domains/emails from a list
umbra file export.csv
umbra path/to/phish.eml                  # bare path routes to umbra file
```

Web: home page **Or analyze a file** → confirm screen (same as search) → run.

---

## What shipped

| Piece | Role |
|-------|------|
| `umbra.email.parse` | Headers, Received chain, trust boundary |
| `umbra.email.verdict` | Alignment / DMARC / spoof findings |
| `umbra.email.plan` | IntentPlan seeds (recipient unchecked by default) |
| `umbra.ingest` | Sniff type → reader → IntentPlan (text/CSV/JSON/email/metadata) |
| CLI | `umbra email`, `umbra file`, path-aware group |
| Web | `POST /ingest` → `results.html` |

---

## Design rules (still law)

- Received hops below the trust boundary are **untrusted**; no invented "origin"
- Authentication-Results only counts above the boundary
- Alignment is the spoof signal, not bare `dkim=pass`
- Selection step required — nothing collects until confirm
- Bytes never written to disk; plan holds identifiers, not the file

Full background and hop semantics remain below for maintainers.

---

## 1. Why this fits Umbra unusually well

It is the most common defensive OSINT task there is — *is this email
phishing?* — and Umbra already has almost all of the machinery.

**23 of the 34 collectors already accept an entity that email headers yield:**

| Entity headers produce | Collectors already waiting for it |
|---|---|
| `domain` | `dns_email_auth`, `domain_reputation`, `rdap_domain`, `dns_resolve`, `tls_cert`, `crtsh`, `ct_lake`, `lookalike_domains`, `security_txt`, `tech_fingerprint`, `malware_infra`, … |
| `ip` | `ip_reputation`, `rdap_ip`, `asn_cymru`, `malware_infra` |
| `email` | `email_split`, `hibp_breach`, `gravatar` |
| `url` | `http_probe`, `html_links`, `wayback_cdx` |

So this is **a parser and a playbook, not a new intelligence capability**. The
work is turning a messy blob into the right entities with the right confidence —
and refusing to state things the headers cannot support.

`dns_email_auth` already covers SPF/DMARC/DKIM policy for a domain. What is
missing is reading what *actually happened to this message*.

---

## 2. The thing that makes this hard, and the thing that makes it dangerous

### Received headers are forgeable below the trust boundary

Each MTA **prepends** a `Received:` header. So the chain reads newest-first, and:

- the **topmost** hops were added by the recipient's own infrastructure and can
  be trusted;
- everything **below the first hop you do not control** was supplied by whoever
  sent the message, and can be **entirely fabricated**.

A spammer writes ten convincing `Received:` lines claiming the mail originated
at a bank. A naive parser reads the bottom of the chain, calls it "the
originating IP", and Umbra confidently reports an innocent third party as the
source of a phishing campaign.

**This is the same failure the whole codebase is built against** — DNSBL errors
rendered as clean, crt.sh outages rendered as no certificates, an unsynced lake
rendered as no sanctions. Here it is worse, because the wrong answer *accuses
somebody*.

**Rule:** the parser marks every hop `trusted` / `untrusted` / `unknown`, and
never names an "origin" it cannot justify. When the boundary cannot be
established, it says so rather than guessing.

### Authentication-Results is forgeable too

`Authentication-Results` is the single highest-value header — SPF, DKIM and
DMARC verdicts for the actual message. It is also **just a header**, and a
sender can write one saying `dmarc=pass`. It only means something when it was
added by the receiving domain, which is the same trust-boundary question.

### Alignment is the real spoofing signal

`dkim=pass` alone means *someone* signed it, not that the sender is who they
claim. The finding is whether the `From:` domain **aligns** with the DKIM `d=`
domain and the `Return-Path`. A message with `From: security@yourbank.com`,
valid DKIM for `d=mailer.random-vps.tld`, and SPF pass for that same stranger is
a textbook spoof that passes all three checks read individually.

---

## 3. Why the intent box is not enough

`analyze_intent` already extracts emails, domains and IPs from free text, so
pasting headers there "works" — badly:

- it would seed the **recipient's own** address, mail servers and internal
  hostnames as investigation targets, producing a graph of the victim's
  infrastructure;
- it cannot tell `From:` from `Return-Path:` from `X-Originating-IP:`, which is
  the entire question;
- it would treat a forged bottom-of-chain relay identically to a verified one.

The parser has to know **which** extracted strings matter, what role each plays,
and how much to trust it.

---

## 4. What gets extracted

| Header | Yields | Notes |
|---|---|---|
| `From`, `Sender` | email + domain | the claim being tested |
| `Reply-To`, `Return-Path` | email + domain | mismatch with `From` is a classic signal |
| `Received` chain | ip, domain, timestamps | trust-marked per hop; the hard part |
| `Authentication-Results` | spf/dkim/dmarc verdicts | only meaningful above the boundary |
| `DKIM-Signature` | `d=` signing domain, `s=` selector | alignment input |
| `Message-ID` | domain | often reveals the true sending host |
| `X-Originating-IP`, `X-Sender-IP` | ip | vendor-specific, low trust |
| `List-Unsubscribe` | url | frequently the actual payload domain |
| `X-Mailer`, `User-Agent` | technology | weak attribution signal |
| `Subject`, `Date` | case naming, timeline | never an entity |

**Not in scope:** message bodies, attachments, HTML rendering, URL detonation.
That is sandbox territory and a different risk posture entirely.

---

## 5. Privacy — the part that needs deciding before code

Headers are **personal data about the recipient**, not just the sender. A pasted
header block typically contains the recipient's address, their employer's
internal hostnames, their mail routing, and timestamps of their behaviour.

**The selection step resolves most of this** (§5a). The analyst sees everything
that was extracted and chooses what runs, so Umbra never has to guess which
identifiers are safe to touch — and never silently touches any of them.

Remaining rules, mirroring the case retention work already shipped:

1. **Never persist the raw header blob.** Parse in memory, store the selected
   entities only. The blob is the most sensitive artifact and has no
   investigative value once parsed.
2. **Recipient-side entities are shown but default to unchecked.** An analyst
   needs them visible to read the Received chain; nobody needs them scanned by
   accident.
3. **A public paste box gets the same 90-day case retention** as everything
   else, and the same self-service delete.
4. The `/legal/privacy` table gains a row before any public write path opens —
   the same ship-blocker rule the phone work followed.

**Open question for Carl:** public paste box, or operator/case-only? My view:
operator-only first. A public box invites people to paste their employer's
internal mail routing into a stranger's website, and the feature is just as
useful behind the case UI while that decision is made.

---

## 5a. The selection step — already built

Carl's refinement: **extract, then let the analyst pick what runs.** That is not
new UI. It is the intent confirm page (`results.html`), which already does
exactly this:

> *Seeds — Uncheck anything the extractor got wrong, no need to retype the
> intent.*

…with a checkbox per seed, collector chips, and `_apply_plan_edits` enforcing
that **edits may only narrow**: a collector that was not in the plan is dropped
rather than run, and the budget caps still apply. That narrowing rule is the
security property, and it is already tested.

So the integration point is simply: **the header parser emits an `IntentPlan`.**
Everything downstream is free — confirm page, narrowing, worker dispatch, case
creation, budgets, audit.

`IntentSeed` already carries every field this needs:

| Field | Used for |
|---|---|
| `include: bool` | sender-side defaults **on**, recipient-side defaults **off** |
| `notes` | *"Return-Path domain — does not match From"*, *"your own mail server"* |
| `source_span` | which header it came from, so a claim is traceable |
| `confidence` | a trusted-hop IP outranks an `X-Originating-IP` |

This is what makes the feature small. The parser is the work; the workflow
exists.

### What the analyst sees

```
Seeds from the header block                              run?
  domain   secure-yourbank-verify.tld   From domain          [x]
  email    security@secure-yourbank…    From                 [x]
  domain   mailer.random-vps.tld        DKIM d= (unaligned)  [x]
  ip       203.0.113.44                 Received, trusted    [x]
  ip       198.51.100.9                 Received, UNTRUSTED  [ ]  ← below the boundary
  domain   mail.carls-employer.com      your own relay       [ ]  ← recipient side
  email    carl@carls-employer.com      recipient            [ ]
```

Unchecked-by-default is not the same as hidden. The analyst can tick the
untrusted hop deliberately — sometimes that is exactly the thing worth looking
at — but it takes a decision, not a default.

---

## 6. Shape

```text
raw headers
  → umbra.email.parse       (headers → structured, trust-marked Received chain)
  → umbra.email.verdict     (alignment + auth → plain-English findings)
  → umbra.email.plan        (→ IntentPlan; sender-side included, rest unchecked)
  → EXISTING confirm page   (analyst selects; edits may only narrow)
  → EXISTING run path       (worker job, capped, audited)
```

New package, mirroring `umbra.phone`:

```text
src/umbra/email/
  __init__.py
  parse.py      # header block → Headers object, Received chain, trust marks
  verdict.py    # pure: alignment, auth, mismatch findings
  extract.py    # → EntityIn list, sender-side only
```

CLI:

```bash
umbra email analyze -f headers.txt        # parse + verdict, no collectors
umbra email triage  -f headers.txt --case <id>   # seed + run the playbook
```

Web: a paste box that renders the parse, then offers "run collectors" as a
second, explicit step — never automatic, since that turns a paste into outbound
traffic against a third party.

---

## 7. Delivery slices

| ID | Slice | Exit criteria |
|----|-------|---------------|
| **E1** | `parse.py` — headers, unfolding, Received chain | fixtures from real MTAs (Google, Microsoft, Postfix, Exchange); malformed input never raises |
| **E2** | Trust boundary + `verdict.py` | forged-chain fixture is not reported as origin; alignment findings correct |
| **E3** | `plan.py` — headers → `IntentPlan` | recipient-side seeds present and `include=False`; sender-side on |
| **E4** | CLI `umbra email analyze` | parse + verdict, no collectors, no network |
| **E5** | Paste box → existing confirm page (operator-gated) | raw blob never persisted; selection drives the run |
| **E6** | Public box + legal text | only if Carl decides it should be public |

E3 is where the reuse pays: once `plan.py` returns an `IntentPlan`, E5 is a
paste box and a redirect into a page that already works.

---

## 8. Tests that must exist

- Real header blocks from **Google, Microsoft 365, Postfix, Exchange** — the
  formats differ enough that one parser written against one of them will break
  on the others.
- **A forged Received chain** claiming a bank origin → asserts Umbra does not
  name it as the source.
- **Aligned pass vs unaligned pass** → the unaligned one is a finding.
- `From` / `Return-Path` / `Reply-To` mismatch.
- Header folding, RFC 2047 encoded words, absurd lengths, missing headers,
  duplicated headers, CRLF vs LF.
- **Recipient identifiers appear but are unchecked**, and untrusted hops too —
  visible for reading the chain, never armed by default.
- Malformed and hostile input never raises.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| Forged chain reported as origin | Trust boundary marking; refuse to name an origin when it cannot be established |
| Forged `Authentication-Results` | Only trusted above the boundary; say which |
| Parser brittleness across MTAs | Fixtures from four real senders before shipping |
| Victim's own infra becomes a target | Shown but unchecked by default; the analyst decides, and a test asserts the defaults |
| Paste box becomes a data-collection hazard | Never persist the blob; operator-only until decided |
| Auto-running collectors on paste | Selection *is* the second step; nothing runs until the analyst submits |

---

## Related

`docs/COLLECTORS.md` (`dns_email_auth`) · `docs/INTENT-SEARCH.md` ·
`docs/ETHICS.md` · `docs/legal/PRIVACY.md` · `docs/PHONE-REPUTATION.md` (the
same shape: parse → entity → existing collectors)

## The organisation boundary (Public Suffix List)

DMARC relaxed alignment is defined in terms of the **organisational domain**, so
`org_domain()` is load-bearing for the entire spoofing verdict.

It used to compute that from 25 hardcoded registry suffixes, with a comment
saying it was "not a public suffix list". The comment was accurate and the cost
ran the wrong way:

| From / DKIM d= | old org_domain | verdict |
|---|---|---|
| `attacker.github.io` vs `victim.github.io` | both `github.io` | **aligned** |
| `evil.herokuapp.com` vs `bank.herokuapp.com` | both `herokuapp.com` | **aligned** |
| `evil.s3.amazonaws.com` vs `corp.s3.amazonaws.com` | both `amazonaws.com` | **aligned** |

Six of these. Each is a DKIM signature from one tenant of a shared host
authenticating a `From:` on another — reported as authenticated. **A spoofing
check that errs toward "authenticated" is the wrong direction to be wrong in.**

The PSL's **PRIVATE** section exists for precisely these namespaces — a company's
own domain handed out to unrelated third parties — and the hardcoded set had
none of them. Both halves count for alignment: two tenants of `github.io` are no
more one organisation than two registrants under `co.uk`.

```bash
umbra psl sync                        # 9,957 rules, ~333 KB, weekly timer
umbra psl check attacker.github.io    # suffix, registrable, and what the verdict uses
```

The built-in fallback stays, and now carries the highest-traffic shared-hosting
suffixes, so a fresh install with no sync is not wrong about the common cases.

### Three ways to be wrong, only one of which is safe

- **Merging two organisations** → false alignment → a spoof reported as
  authenticated. The failure this change removes.
- **Splitting one organisation** → real mail reported as misaligned. Tested
  against subdomain cases so the fix does not overshoot.
- **Not knowing** → must never render as either. `org_domain` returns None only
  when the loaded list says the host *is* a public suffix; an unknown TLD falls
  back rather than returning None, because callers comparing
  `org_domain(a) == org_domain(b)` would read `None == None` as **aligned**.
  `verdict._aligned` guarded that; `plan.py` did not, until this change made the
  disagreement reachable.
