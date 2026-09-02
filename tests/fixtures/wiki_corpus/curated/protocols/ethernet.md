---
slug: protocol/ethernet
title: Ethernet (IEEE 802.3 family)
page_type: protocol
tags: [network, l2]
standards: [IEEE-802.3]
related:
  - protocol/arp
provenance: curated
updated_at: 2026-08-14
sources:
  - name: IEEE 802.3 overview
    url: https://standards.ieee.org/ieee/802.3/
---

# Ethernet

Ethernet is the dominant family of **wired LAN** technologies (IEEE 802.3). Frames carry payloads such as IPv4/IPv6; ARP operates alongside IPv4 on Ethernet-like links. Full IEEE standard text is **not** redistributed here — use official IEEE sources for normative requirements.

## OSINT / IR relevance

- MAC addresses (OUIs) identify vendor class of NICs
- Switch CAM tables and DHCP logs pair IP ↔ MAC for asset inventory
