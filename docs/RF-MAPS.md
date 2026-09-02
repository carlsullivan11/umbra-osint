# RF / wireless maps

**Collector:** `wifi_maps` (38)  
**Not a scrape of** wigle.net / openwifimap.net / deflock.me map UIs.

| Source | What Umbra uses |
|--------|-----------------|
| [WiGLE](https://wigle.net/) | Portal + optional API (`UMBRA_WIGLE_API_NAME` / `UMBRA_WIGLE_API_TOKEN`) for a **BSSID**. No bulk dump. |
| [OpenWifiMap](https://openwifimap.net/) | Portal link (community mesh). No world-dump download. |
| [Deflock](https://deflock.me/) | Recreated from **OSM Overpass** (`man_made=surveillance`, ALPR tags) near a geocoded city. |
| [WaveDigger / Network Survey](https://networksurvey.app/wavedigger/) | Portal + ingest of **your** survey JSON (`props.rf_survey`). Own scans, own_asset. |

**Graph:** MAC `observed_at` LOCATION (last-seen). Cameras as LOCATION. Randomized MACs skipped.

Last-seen WiFi is **not** a home address.

## Owned RF lake

`data/lake/rf.sqlite` — **only** OSM cameras (and optional WiGLE hits / survey rows) for packed cities.

```bash
umbra rf sync          # Nominatim + Overpass, ~10 cities, ~4 km
umbra rf status
umbra rf cameras "Bentonville"
```

| Action | CLI | Web |
|--------|-----|-----|
| Look up cameras | `umbra rf cameras "Oakland"` | `GET /v1/rf/cameras?q=` |
| RF lake status | `umbra rf status` | `GET /v1/rf` |

Person graph hydrate (`umbra people graph`) geocodes residence / land situs / SOR address from the **cached** city centroids, then attaches cameras **within 6 km** — not just a string match on `"Oakland"`.

Daily: Hermes `umbra_rf_sync_tick.py` 07:15 (needs gateway; **900s** budget) and host `umbra-rf-sync.timer` 07:15 UTC.

**Both budgets exist for the same reason.** Overpass makes callers queue for a
slot and the wait can exceed 180s *per city*, across 14 cities. The Hermes
wrapper died at 180s (2026-08-31/09-01); `umbra-rf-sync.service` sets
`TimeoutStartSec=3600` because systemd's 90s default would SIGTERM the run even
sooner — and silently, since the unit still writes its log. A verified run on
2026-09-01 took **5m10s**, well past that default.

Geocodes are read from the lake before Nominatim is called. City centroids do
not move, so re-geocoding the same 14 cities daily was pure cost against a
rate-limited public service.

