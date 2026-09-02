# File ingest (upload / CLI)

**Status:** shipped  
**Code:** `src/umbra/ingest/` · `src/umbra/cli/file_cmd.py` · `POST /ingest`

## What it does

Turn a file into an **`IntentPlan`** (same confirm path as search):

| Kind | Reader |
|------|--------|
| Email (`.eml`, headers) | `umbra.email` — alignment, Received trust, seeds |
| Text / log of IOCs | extract IPs, domains, emails, URLs |
| CSV / TSV / JSON | flatten values then extract |
| JPEG / PNG / TIFF | EXIF metadata, including GPS position |
| PDF | Info dictionary + XMP, inflating object streams |
| DOCX / XLSX / PPTX | `docProps` author, company, external links |

Nothing is collected until the analyst confirms. Upload bytes stay in memory.

**Detection is by content, not by name** — a PDF called `notes.txt` is read as a
PDF. The filename only breaks ties: `*.eml` plus at least two real mail headers
routes to the mail reader even when content sniffing is unsure, because the
generic text extractor cannot tell a sender from a recipient and would arm the
recipient's own address.

For messages, sender-side identifiers are checked by default; the recipient,
their own relays, and every hop below the trust boundary are **shown and
unchecked**. See `docs/EMAIL-HEADERS.md`.

## CLI

```bash
umbra example.email          # a bare path that is not a command name
umbra file indicators.txt
umbra file sample.eml --confirm
umbra email headers.txt --trusted-domain example.com
printf '8.8.8.8\n' | umbra file -
```

## Web

Home → **Analyze file** → multipart `POST /ingest` → confirm checkboxes → `/run`.

Limits: 5 MB body, 20k lines, 500 seeds; rate limit `/ingest` 30/5min.

## Related

`docs/EMAIL-HEADERS.md` · `docs/INTENT-SEARCH.md` · `docs/ETHICS.md`
