---
slug: concept/arp-cache-poisoning
title: ARP cache poisoning
page_type: concept
tags: [network, mitm, spoofing, l2]
mitre_ids: [T1557.002]
related:
  - protocol/arp
  - protocol/ethernet
  - concept/adversary-in-the-middle
provenance: curated
updated_at: 2026-08-14
sources:
  - name: MITRE ATT&CK T1557.002
    url: https://attack.mitre.org/techniques/T1557/002/
---

# ARP cache poisoning

**ARP cache poisoning** (ARP spoofing) is an adversary-in-the-middle technique where an attacker sends forged ARP replies so victims associate the attacker’s MAC with a legitimate IP (often the default gateway). Traffic can then be intercepted, modified, or denied on the local segment.

## MITRE

- **T1557.002** — Adversary-in-the-Middle: ARP Cache Poisoning

## Defensive

- Switch features: DAI, port security, DHCP snooping bindings
- Detect gateway MAC flapping / multiple MACs per IP
- Segment untrusted clients (guest Wi‑Fi)

## Not the same as

- DNS spoofing (different layer; see DNS security topics)
- Public routing attacks (BGP) — different domain
