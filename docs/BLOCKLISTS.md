# Public DNS blocklists

**Status:** shipped  
**Endpoints:**
- Malware: `/lists/malware-domains.txt` (+ hosts / ips / adblock)
- Adult: `/lists/adult-domains.txt` (+ hosts / adblock)
**Wiki:** `tool/dns-blocklist` in umbra-wiki  

### Sources
- Malware: owned abuse.ch lake (URLhaus, ThreatFox, Feodo)
- Adult: Blocklist Project + StevenBlack porn lists (cached 24h)

Pi-hole / AdGuard:

```text
https://umbra-osint.com/lists/malware-domains.txt
https://umbra-osint.com/lists/adult-domains.txt
```
