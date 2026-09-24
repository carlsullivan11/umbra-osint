# Open core · freemium web · paid advanced

**Vault:** `Documents/CarlsVault/Projects/OSINT/Umbra-Open-Core-Private-Cloud.md`

## User-facing tiers (Carl 2026-08-15)

| | Free (core) | Paid (advanced) |
|--|-------------|-----------------|
| **Website** | ✅ same core as CLI/plugin | ✅ analytics, DS, premium, team, … |
| **CLI** | ✅ local OSS + optional free cloud | ✅ via API key |
| **Obsidian** | ✅ same core | ✅ via API key |

- Core is **free on all surfaces** (parity).  
- Advanced is **paid**, usable on **web and** CLI/plugin (API key).  
- Local CLI/plugin core works **offline without an account**.

## Code visibility

| Public source | Private source |
|---------------|----------------|
| CLI package, Obsidian plugin, umbra-wiki | Hosted web, billing, paid feature impl, deploy |

**Where the line is actually held** (2026-09-02). It used to be one line of
packaging config — `exclude = ["umbra.web*"]` in `pyproject.toml`. That is
enough for a PyPI wheel, which ships only what it is told to, and not enough
for a public git repository, where the history and every unshipped file are
visible too.

`scripts/publish_open_core.py` is the boundary as code. It generates the
public tree from this one, refuses to publish when its secret scan hits, and
with `--check` installs the result into a fresh venv and runs its tests with
`umbra.web` genuinely absent — the only way to know the open core stands alone
rather than assuming it.

| | |
|--|--|
| Public repo | <https://github.com/carlsullivan11/umbra-osint> (MIT, generated) |
| Corpus repo | <https://github.com/carlsullivan11/umbra-wiki> (MIT, hand-maintained) |
| PyPI | `pip install umbra-osint` |

The public repo is a **mirror, not a fork**: fix things in this tree and
republish. Editing it directly makes the two diverge, which is exactly what the
generator exists to prevent.

At the first publish: 334 files out, 253 held back, 1,362 tests passing in
isolation.

## Engineering rule

```text
Free core feature  → CLI + Web free UI + Plugin + /v1 (free)
Paid feature       → Web paid UI + /v1 (entitled) + CLI/plugin hooks
```

Entitlements: `GET /v1/me` → tier + feature flags.
