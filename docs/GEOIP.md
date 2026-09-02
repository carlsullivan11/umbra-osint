# IP geolocation (owned lake)

**Status:** shipped collector `ip_geo` + CLI `umbra geoip`  
**Source:** free [DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite) (CC-BY 4.0)  
**Code:** `src/umbra/lake/geoip.py` · `src/umbra/collectors/ip_geo.py` · `src/umbra/cli/geoip_cmd.py`

## Why this design

| Option | Why not / why |
|--------|----------------|
| MaxMind GeoLite2 | Free but **license key** required to download |
| Live ip-api / ipinfo HTTP | Rate limits, no offline cases, SSRF surface |
| Full MaxMind commercial | Paid |
| **DB-IP City Lite CSV → SQLite** | Free monthly dump, CC-BY, offline lake, no key |

## Operator

```bash
umbra geoip sync
umbra geoip status
umbra geoip lookup 1.1.1.1

# air-gap / offline import
umbra geoip import-csv /path/to/dbip-city-lite-YYYY-MM.csv.gz
```

Env:

| Var | Meaning |
|-----|---------|
| `UMBRA_GEOIP_DB` | Override SQLite path (default `$data_dir/lake/geoip.sqlite`) |
| `UMBRA_DATA_DIR` | Root for default path |

Prod: `umbra-geoip-sync.timer` runs this monthly (DB-IP publish City Lite
monthly, so anything shorter is traffic for an unchanged file). Disk ~ hundreds
of MB for the SQLite lake depending on edition.

This was the only lake without a timer, so in practice it went unloaded — and
every IP in every case then reported *"GeoIP lake not loaded — location is
unchecked, not empty"*, once per affected entity. Freshness is now reported by
`umbra doctor` instead of inside each run's notes.

## Graph output

- IP props: `geo_country`, `geo_region`, `geo_city`, `geo_latitude`, `geo_longitude`, `geo_source`
- `LOCATION` entities (city label + country)
- Edges: `located_in`
- Evidence cites DB-IP; notes warn about VPN/CGNAT/anycast

## Honesty

- Unsynced lake → collector notes **unchecked** (not “no location”)
- Private/reserved IPs → no lookup
- City DB is **approximate** — never street-level certainty

## License / attribution

When redistributing products that embed these results, attribute:

> IP Geolocation by DB-IP (https://db-ip.com)

## Related

- Country codes also appear on `rdap_ip` / `asn_cymru` (registration / ASN), which can **disagree** with city geo — that is expected.
- Phase D geospatial module is broader map UI; this is the data plane.
