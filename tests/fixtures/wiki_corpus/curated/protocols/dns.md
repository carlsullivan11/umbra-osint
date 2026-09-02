---
slug: protocol/dns
title: Domain Name System (DNS)
page_type: protocol
tags: [network, dns, infrastructure]
related:
  - concept/email-authentication
standards: [RFC1034, RFC1035]
provenance: curated
updated_at: 2026-08-14
sources:
  - name: RFC 1035
    url: https://www.rfc-editor.org/rfc/rfc1035
---

# Domain Name System (DNS)

DNS maps names to records (A/AAAA, MX, TXT, NS, etc.). It is foundational for almost every internet investigation: passive DNS, CT correlation, mail auth (SPF/DKIM/DMARC TXT), and reputation via DNSBLs.

## Umbra collectors (typical)

- `dns_resolve`, `dns_email_auth`, DNSBL reputation paths (local recursive resolver required for blocklists)
