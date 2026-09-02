---
slug: protocol/arp
title: Address Resolution Protocol (ARP)
page_type: protocol
tags: [network, l2, ipv4]
mitre_ids: [T1557.002]
related:
  - concept/arp-cache-poisoning
  - protocol/ethernet
standards: [RFC826]
provenance: curated
updated_at: 2026-08-14
sources:
  - name: RFC 826
    url: https://www.rfc-editor.org/rfc/rfc826
---

# Address Resolution Protocol (ARP)

ARP resolves an **IPv4 address** to a **link-layer (MAC) address** on a local network segment. Hosts cache answers in an ARP table. There is no cryptographic authentication in classic ARP, which enables **ARP cache poisoning** (adversary-in-the-middle on L2).

## Operator notes

- Scope is **local broadcast domain** — not a public-Internet lookup protocol.
- Monitoring: unexpected MAC changes for a gateway IP are a classic detection signal.
- Related hardening: Dynamic ARP Inspection (DAI) on switches, static ARP for critical pairs, 802.1X segmentation.

## See also

- [[concept/arp-cache-poisoning]]
- MITRE ATT&CK T1557.002
