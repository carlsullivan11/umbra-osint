# DNS Service for Umbra

**Status:** Production-aligned 2026-08-13 — host Unbound (full recursion) + DNSBL-aware Python resolver

---

## Correct design (source of truth)

| Query type | Function | Public `1.1.1.1` failover? |
|---|---|---|
| Ordinary A/TXT (lookalikes, ASN, general) | `resolve_a_record`, `get_resolver()` | **Yes** — public resolvers answer these correctly |
| **DNSBL** (Spamhaus zen/dbl) | `dnsbl_lookup()` = `get_resolver(allow_public_failover=False)` | **No** — there is no valid public fallback for a blocklist |

Code: `src/umbra/core/dns.py`  
Config: `UMBRA_DNS_RESOLVER=<local recursive resolver IP>`

### The container trap: system resolvers are public too

Stripping the *explicit* `1.1.1.1` failover is not sufficient. When no primary
is configured, dnspython falls back to `/etc/resolv.conf` — and inside a Docker
container that is typically **`1.1.1.1` / `8.8.4.4`** (verified on this host:
the API/test containers inherit the host's upstream resolvers plus `1.1.1.1, 8.8.4.4`, while the host
itself has only `127.0.0.53`). So an unset `UMBRA_DNS_RESOLVER` would silently
send DNSBL queries through a public resolver and mark **every** address listed.

`get_resolver(allow_public_failover=False)` therefore also filters
`PUBLIC_RESOLVERS` out of the system fallback. If nothing safe remains,
`dnsbl_lookup()` returns an **error** naming `UMBRA_DNS_RESOLVER` rather than
querying — never "clean", never "listed".

Found by the containerized deploy gate: the test asserting no public failover
passed locally and failed in the container, which is exactly the class of
environment-specific bug the gate exists to catch.

### Why not “always fail over to 1.1.1.1”
1. **Spamhaus refuses public resolvers** and answers with `127.255.255.x`. Treating any answer as “listed” caused **100% false positives**.
2. **Bare hostname `"unbound"` is invalid** as a dnspython nameserver (must be an IP).
3. **Resolver errors must never look like “clean”.**

---

## Zen return codes are not interchangeable (2026-09-13)

Rule 3 above was stated here from the start and broken one layer up: the
*lookup* distinguished error from not-listed, and the *scoring* then collapsed
them. `confidence = hit.weight if hit.listed else 0.5` gave a resolver failure
and a confirmed negative the same 0.50. `ReputationHit.checked` now carries the
distinction, `evidence_confidence()` scores an unchecked source at 0.1, and a
lookup where **every** source errored returns `unknown` rather than `clean`.

The codes themselves were also flattened — any Zen listing scored 0.6.

| code | meaning | weight |
|---|---|---|
| `127.0.0.2` | SBL — direct spam source | 0.60 |
| `127.0.0.3` | SBL CSS — snowshoe infrastructure | 0.50 |
| `127.0.0.4`–`.7` | XBL — compromised device, open proxy, worm | 0.60 |
| `127.0.0.9` | SBL DROP — hijacked netblock | 0.85 |
| `127.0.0.10`, `.11` | **PBL — end-user address** | **0.00** |

**PBL is a policy listing, not an accusation.** It says an address is end-user
space that should not deliver mail directly, which is true of essentially every
residential IP. On production, 53 of 692 listings were PBL-only and each was
reported as `listed in zen.spamhaus.org (127.0.0.11)` at 0.6 — escalated to
**suspicious** for being somebody's home broadband.

PBL hits now carry `scope="policy"`, which `verdict_from_hits()` excludes from
the verdict the same way it excludes Tor relay roles: **reported, never
counted**. An unrecognised code is described verbatim rather than guessed at.

---

## Unbound Docker image failure (historical)

Attempts with `mvance/unbound` / `klutchell/unbound` failed:
- Strict image config paths and syntax errors on `unbound.conf`
- `forward-zone` to public DoT resolvers **breaks DNSBL** even if the container starts
- Crash-looping container was removed from the production compose stack

**Do not** put Unbound back in Docker as a forwarder to 1.1.1.1/9.9.9.9.

---

## Production setup (VPS — verified)

### Host Unbound (apt)
- Package: `unbound` (systemd enabled)
- Listens: `127.0.0.1:53` and **`172.17.0.1:53`** (docker0 — so containers can reach the host resolver)
- Config drop-in: `/etc/unbound/unbound.conf.d/umbra-recursive.conf`
- **Full recursion** — no `forward-zone`
- Access: localhost + RFC1918/Docker networks

### Umbra API wiring
```bash
# Inside API container, 127.0.0.1 is the container itself — NOT the host.
# Use the docker0 bridge IP so DNSBL works from umbra-api:
UMBRA_DNS_RESOLVER=172.17.0.1
```

Set in `/opt/umbra/.env` and `docker-compose.yml` under `api.environment`.

### Verified checks
```text
# Host
dig @127.0.0.1 2.0.0.127.zen.spamhaus.org +short   → 127.0.0.2 / .4 / .10  (LISTED)
dig @127.0.0.1 1.1.1.1.zen.spamhaus.org +short     → (empty)               (not listed)
dig @127.0.0.1 example.com +short                  → public A records

# API container (Python)
dnsbl_lookup("2.0.0.127.zen.spamhaus.org") → status=listed
dnsbl_lookup("1.1.1.1.zen.spamhaus.org")   → status=not_listed
```

### Repo mirror config
`deploy/unbound.conf` — reference recursive config for documentation / future hosts (no forward-zone).

---

## Collector coverage

All DNS-using collectors go through `umbra.core.dns.get_resolver()` / `dnsbl_lookup()`:
`ip/domain_reputation` (DNSBL, no public failover), `lookalike_domains`, `asn_cymru`,
`dns_email_auth`, `dns_resolve`, watch `monitor`.

---

## Future phases (not production yet)

- **Phase 2:** Private filtered DNS for authorized users  
- **Phase 3:** Public ad/malware filtering DNS product  

---

*Last updated: 2026-08-13 — docs matched to live VPS (host Unbound + docker0 gateway)*
