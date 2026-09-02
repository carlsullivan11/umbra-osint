# Breach Exposure & Dark-Web Monitoring — Design

## What we build (defensive)

1. **Email breach exposure** via [Have I Been Pwned](https://haveibeenpwned.com/) API (`hibp_breach` collector + `umbra breach email`)
2. **Password exposure** via HIBP Pwned Passwords **k-anonymity** range API (`umbra breach password` — full password never leaves the host)
3. **Remediation plans** generated from breach data classes (password change, MFA, credit freeze, etc.)
4. **Graph integration** — `email —exposed_in→ breach` entities on a case; profile breach section
5. **Watchlist email checks** — `umbra watch add -t email` + `umbra watch check` snapshots HIBP breach **names** and diffs over time

## Policy (set 2026-08-13): passive & defensive only

Umbra performs **passive, defensive dark-web exposure monitoring of authorized
assets only** — the line is **observation, never participation**. Full policy
in [ETHICS.md](ETHICS.md); plan in the vault (Projects/OSINT/Umbra-DarkWeb-Monitoring).

**Permitted:** read-only detection of *your/authorized* asset exposure in
already-public sources (feeds, paste sites, public channels, clearnet-indexed
.onion), recording the *fact* of exposure with provenance.

## What we deliberately do NOT build — permanent non-goals

Not future phases. Never:
- Purchasing stolen data or access
- Contacting/negotiating with sellers or criminal communities; undercover personas
- **Crawling or scraping criminal marketplaces / crime forums** to pull dumps
- Re-hosting or re-distributing stolen data (store the *fact* of exposure, not a copy)
- Facilitating or profiting from any criminal market

Reasons unchanged: high legal/abuse risk, malware-laden sources, and HIBP +
commercial CTI feeds already normalize this into **lawful APIs**. Umbra is a
**defensive exposure & hardening** tool, not a stolen-data acquisition engine.

## "Dark web monitoring" — legitimate architecture

| Layer | Approach | Status |
|-------|----------|--------|
| Breach corpus | HIBP API | **Implemented** |
| Password corpus | HIBP Passwords range API | **Implemented** |
| Email watch diffs | `umbra watch check` on email items | **Implemented** (needs API key) |
| Ransomware leak-site exposure | `ransomware_exposure` collector — is your domain/org a named victim? (ransomware.live public index, key-free, passive) | **Implemented** |
| Stealer-log / infostealer intel | Lawful feeds (keyed adapters: DeHashed, IntelX, ransomware.live v2), authorized assets | Planned (adapters stubbed, key-gated) |
| Public paste monitoring | Authorized assets (own/client domains & emails) | Future |
| Ahmia / clearnet-indexed .onion research | Read-only, passive | Future |
| Sandboxed read-only Tor page reads | Isolated egress, no logins/forms/downloads/txns | Future, high-care |
| **Crawling/scraping criminal markets or forums** | **Permanent non-goal** | Rejected |
| **Purchasing / seller contact / redistribution** | **Permanent non-goal** | Rejected |

## CLI

```bash
export UMBRA_HIBP_API_KEY=...   # https://haveibeenpwned.com/API/Key

# Password (no API key needed)
umbra breach password

# Email → table + remediation markdown
umbra breach email you@example.com
umbra breach email you@example.com --case <case_id>

# Graph collector
umbra run <case_id> -c hibp_breach

# Continuous watch
umbra watch add -t email -v you@example.com
umbra watch check
```

## Watches in the web UI (W1, 2026-08-16)

Watches were a backend feature for most of the project's life: created from the
CLI, by the operator, on their own machine. `/watches` and the **Watch for
changes** control on a case page put a form in front of the same monitor, which
changes the threat model more than it changes the feature.

| Decision | Why |
|---|---|
| A watch belongs to a **case** | Visibility runs through `case.owner_id` like the case itself, so the cascading delete and the 90-day retention sweep already take watches with them. An orphaned watch would poll a stranger's domain forever with nobody able to stop it — which is why retention shipped first. |
| `_http_snapshot` uses **`GuardedClient`** | A visitor who can name a host and have the server fetch it on a timer has an SSRF primitive. The guard already covered collectors; this path was missed only because nothing public could reach it. |
| The target is checked **at creation**, not just at fetch | A refusal that happens hourly in a log nobody reads is worse than one the visitor sees immediately. |
| A name that **does not resolve** is still watchable | `check_url` fails closed on NXDOMAIN, but a parked lookalike getting its first A record is exactly the change worth being told about. Resolving to a *private* address is refused. |
| **10 watches per case**, rate-limited | Recurring background egress created from an anonymous form. The ceiling is the difference between a monitoring feature and a free scanning service. |
| Only **domain** and **email** are offered | `check_watch_item` answers "unsupported watch type for auto-check" for everything else, and email needs a HIBP key. A watch that can never produce a diff renders as "nothing has changed" — the same unchecked-reads-as-clean failure as a dead DNSBL. |
| Checked every **6 hours** by `umbra-watch-check.timer` | Every tick is real egress to someone else's infrastructure on their behalf; DNS and hosting changes are not minute-scale events. |

`umbra watch check` exits **2 when it finds changes**. That is the interesting
outcome, not a failure — `deploy/scripts/watch_check.sh` treats it as success so
the timer does not go red exactly when the feature worked.

## Authorization

Only check emails/domains you own or are contracted to monitor.  
Same case `authorization_basis` rules as the rest of Nexus.

## Remediation philosophy

Every exposure report ends in **actions**, not fear:
- Credential unique + rotated
- MFA
- Email account lockdown (forwarding rules, sessions)
- Financial / identity steps when SSN/cards involved
