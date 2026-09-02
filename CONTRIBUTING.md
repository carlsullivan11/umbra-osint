# Contributing

Thanks for interest in Umbra.

## Product boundaries

- Read [docs/ETHICS.md](docs/ETHICS.md) — **lawful use only**; operators are responsible for legality.  
- Read [docs/OPEN-CORE.md](docs/OPEN-CORE.md) — public CLI/wiki vs private hosted cloud.  
- Do not contribute features whose **primary purpose** is committing crimes (intrusion, CSAM, fraud tooling, stolen-data marketplaces).  
- Do not commit secrets, customer data, or live API keys.

## Repos

| Repo | What to PR |
|------|------------|
| This repo (`umbra-osint`) | CLI, OSS collectors, wiki engine, docs, tests |
| [umbra-wiki](https://github.com/carlsullivan11/umbra-wiki) | Curated wiki pages, importers (see that CONTRIBUTING) |
| Future `umbra-obsidian` | Plugin UI talking to local/cloud API |
| Private cloud | Not open for public PRs |

## Dev setup

```bash
git clone https://github.com/carlsullivan11/umbra-osint.git
cd umbra-osint
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Pull requests

1. One logical change per PR.  
2. Add/update tests; `pytest -q` must pass.  
3. Update docs (`COLLECTORS.md`, `ETHICS.md`, etc.) when behavior changes.  
4. Conventional commit messages preferred (`feat:`, `fix:`, `docs:`).  
5. Sign off that your contribution is MIT-licensed (same as the project).

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) — do not file public issues for vulnerabilities.
