# Confidence scoring

## Command
```bash
umbra score <case_id>
umbra score <case_id> --dry-run
umbra score <case_id> -o /tmp/scores.md
```

Runs automatically at the end of `umbra run`.

## Model (heuristic)
```
score = clamp(
  0.35 * base_confidence
+ 0.15 * type_prior
+ 0.20 * max_collector_trust
+ 0.10 * mean_collector_trust
+ multi_collector_bonus
+ evidence_bonus
+ strong_edge_bonus
+ degree_bonus
+ same_as_bonus
+ seed_boost
+ special_props (hibp, gravatar, resolved lookalike)
- penalties (orphan, single username probe, disputed)
)
```

### Overrides
| verification | score |
|--------------|------:|
| `true` | 0.97 |
| `false` | 0.05 |
| `disputed` | penalty -0.20 |

### Bands
| Band | Range |
|------|-------|
| high | ≥ 0.85 |
| medium | ≥ 0.60 |
| low | ≥ 0.35 |
| speculative | < 0.35 |

### Collector trust (examples)
- dns/tls/rdap/asn/hibp: high (0.85–0.95)
- github_commits / html_links: medium
- username_presence / ddg_search: lower (noisy alone)

Breakdown stored at `entity.props.score_breakdown` and `score_band`.

## Operator loop
1. `umbra run` / collectors
2. `umbra score <case>` (auto after run)
3. Review speculative list in profile / score report
4. `umbra entity verify` true/false
5. `umbra score <case>` again to lock scores

## AbuseIPDB on a Tor relay (2026-09-16)

Enabling `UMBRA_ABUSEIPDB_API_KEY` had a side effect worth recording.

AbuseIPDB rates `185.220.101.1` at **abuse confidence 100%, 285 reports**. True,
and expected: it is a busy Tor exit, and a busy exit collects hundreds of reports
as its *baseline* — traffic from thousands of strangers leaves through it and the
complaints land on the relay's address.

Measured before and after the key:

| hits | before | after |
|---|---|---|
| tor + spamhaus_zen | suspicious 60 | malicious 99 |
| **tor + abuseipdb only** | **clean 0** | **malicious 99** |

The second row is the defect: running a relay became malicious 99/100 on its own.
`_NON_ACCUSATORY` exists to prevent exactly that and names `tor_exit`/`tor_relay`;
AbuseIPDB carries the same fact in laundered form and walked past the guard.

`_AGGREGATE_SOURCES` now marks sources whose score is a sum of third-party
complaints rather than a finding about the host. On an address already known to
be a Tor relay, those are **reported but cannot decide a verdict**. A *specific*
listing is unaffected — Feodo naming it as C2 still reads malicious 95 — and on
any non-Tor address AbuseIPDB decides exactly as before.
