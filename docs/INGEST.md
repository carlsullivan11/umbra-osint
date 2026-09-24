# File ingest (upload / CLI)

**Status:** shipped  
**Code:** `src/umbra/ingest/` · `src/umbra/cli/file_cmd.py` · `POST /ingest`

## What it does

Turn a file into an **`IntentPlan`** (same confirm path as search):

| Kind | Reader |
|------|--------|
| Email (`.eml`, `.email`, headers) | `umbra.email` — alignment, Received trust, seeds |
| Text / log / md of IOCs | extract IPs, domains, emails, URLs |
| CSV / TSV / JSON / ndjson | flatten values then extract |
| HTML / XML / YAML | text extract (no JS execution) |
| ICS / VCF | calendar / vCard as text |
| JPEG / PNG / TIFF / GIF / WEBP / BMP | EXIF metadata, including GPS |
| PDF | Info dictionary + XMP |
| DOCX / XLSX / PPTX | `docProps` author, company, external links |
| ODT / ODS / ODP | OpenDocument `meta.xml` |

Nothing is collected until the analyst confirms. Upload bytes stay in memory.

**Detection is by content, not by name** — a PDF called `notes.txt` is read as a
PDF. Gzip wrappers are inflated (capped) before sniffing.

## CLI

```bash
umbra search iocs.txt
umbra search hosts.csv
umbra analyze photo.jpg
umbra analyze report.pdf
umbra analyze message.eml
umbra example.email          # bare path
umbra file indicators.txt
umbra email headers.txt --trusted-domain example.com
printf '8.8.8.8\n' | umbra file -
```

`search` and `analyze` are the same engine as `umbra file` (plan, not collect).
`--confirm` runs the armed identifiers.

Limits: 5 MB body, 20k lines, 500 seeds; rate limit `/ingest` 30/5min.

## Related

`docs/EMAIL-HEADERS.md` · `docs/INTENT-SEARCH.md` · `docs/ETHICS.md`
