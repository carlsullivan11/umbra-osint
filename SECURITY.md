# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `master` / latest release | Yes |
| Older tags | Best effort |

## Reporting a vulnerability

**Do not** open a public GitHub issue for security flaws that could harm operators or hosted users.

Email: **security@umbra-osint.com**  
(If that mailbox is not live yet, use the maintainer contact on the GitHub org profile and prefix the subject with `[SECURITY]`.)

Please include:

- Description and impact  
- Steps to reproduce or proof-of-concept  
- Affected component (CLI, web, wiki, deploy, plugin)  
- Whether you plan public disclosure and preferred timeline  

## What to expect

- Acknowledgement when the mailbox is monitored (target: within 7 days)  
- No bounty program unless separately announced  
- We may ask for clarification or a fix review  

## Safe harbor

We will not pursue legal action against researchers who:

- Report in good faith  
- Avoid privacy violations, data destruction, and service disruption beyond minimal PoC  
- Do not access other users’ data on hosted instances  
- Give reasonable time to fix before full public disclosure  

## Hosted service

Production is operator-controlled infrastructure (e.g. Cloudflare Access, private origins).  
Compromising shared hosted tenants or other customers’ investigation data is **out of scope** for “fun” testing without written permission.

## Secrets

If you find credentials in a repository or release artifact, report them immediately so they can be rotated.
