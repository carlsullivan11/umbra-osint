---
slug: concept/email-authentication
title: Email authentication (SPF, DKIM, DMARC)
page_type: concept
tags: [email, dns, spoofing]
related:
  - protocol/dns
provenance: curated
updated_at: 2026-08-14
---

# Email authentication

**SPF**, **DKIM**, and **DMARC** are DNS-published controls that reduce direct domain spoofing in email. Investigators read TXT records and alignment results to grade spoofability.

- **SPF** — which IPs may send for a domain
- **DKIM** — cryptographic message signatures
- **DMARC** — policy + alignment (reject/quarantine/none)

Umbra’s `dns_email_auth` collector deep-dives these records for a domain seed.
