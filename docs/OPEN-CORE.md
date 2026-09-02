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

## Engineering rule

```text
Free core feature  → CLI + Web free UI + Plugin + /v1 (free)
Paid feature       → Web paid UI + /v1 (entitled) + CLI/plugin hooks
```

Entitlements: `GET /v1/me` → tier + feature flags.
