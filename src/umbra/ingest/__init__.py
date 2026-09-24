"""One upload, several kinds of file, always an `IntentPlan`.

Carl's ask, 2026-08-19:

> "this file upload will expand the features to parse a text file of multiple
> IPs or an email file or other file types that it's easy to get metadata from
> for analysis."

The shape that makes that work is the same one the email header feature
landed on: **every reader returns an `IntentPlan`**. From there the confirm page
(`results.html`), the narrow-only edit rule (`_apply_plan_edits`), the worker
dispatch, the budgets and the audit trail already exist. Adding a file type is
adding a reader — not a pipeline, not a UI, not a permission model.

Uploads are the most hostile input this codebase accepts, so every reader works
under the same rules:

* **Size-, line- and seed-capped**, and never silently — a truncated read that
  says nothing reads as "that was all of it", which is the same failure as an
  unreachable source rendering as a clean result.
* **Never written to disk.** The bytes are parsed in memory and dropped. The
  plan carries a description of the file, never its contents, because the plan
  is what gets persisted as a case.
* **Never raises.** A malformed upload is a note, not a stack trace.
* **No network and no LLM.** An uploaded file can be somebody else's
  confidential data.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

from umbra.email.parse import ParsedEmail
from umbra.email.verdict import Finding
from umbra.ingest.detect import Kind, TEXT_KINDS, META_KINDS, decode, sniff
from umbra.intent.plan import select_collectors
from umbra.intent.schema import IntentPlan

logger = logging.getLogger(__name__)

# Comfortably larger than any header block or indicator list, small enough that
# a browser upload cannot become a memory problem. Images with EXIF are the
# reason it is megabytes rather than kilobytes.
MAX_BYTES = 5 * 1024 * 1024
MAX_LINES = 20_000
MAX_SEEDS = 500

_SAFE_NAME = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_ "


@dataclass
class IngestResult:
    """What one file turned into."""

    kind: Kind
    filename: str
    size: int
    plan: IntentPlan
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # The parsed message, for email uploads only. Carried so a caller that wants
    # to render the Received chain does not have to parse the block a second
    # time. Ephemeral like the rest of this object — it is never persisted, and
    # the plan still carries only a description of the file.
    parsed: "ParsedEmail | None" = None


def safe_name(filename: str) -> str:
    """A display name that cannot be a path, and cannot be very long.

    The name comes from whoever uploaded the file, and it ends up in a case
    name that is rendered on a page. Both path separators get stripped, not
    just the platform's own — a Windows client will happily send
    `C:\\Users\\x\\phish.eml`.
    """
    name = (filename or "").strip()
    if not name:
        return "upload"
    name = PureWindowsPath(PurePosixPath(name).name).name
    cleaned = "".join(c for c in name if c in _SAFE_NAME).strip(" .")
    return (cleaned or "upload")[:100]


def _cap_seeds(plan: IntentPlan, notes: list[str]) -> IntentPlan:
    """Keep the strongest seeds, and say how many were dropped.

    Seeds arrive sorted included-first then by confidence, so the trim keeps
    what an analyst would have kept. Collectors are recomputed afterwards —
    otherwise the plan could ask for a collector no remaining seed can feed.
    """
    if len(plan.seeds) <= MAX_SEEDS:
        return plan
    dropped = len(plan.seeds) - MAX_SEEDS
    plan.seeds = plan.seeds[:MAX_SEEDS]
    plan.collectors = select_collectors(plan.seeds, plan.flags)
    note = (f"{dropped} lower-confidence identifier(s) beyond the {MAX_SEEDS} "
            f"cap were not included — the file holds more than one run's worth")
    notes.append(note)
    plan.warnings.append(note)
    return plan


def _read_text(data: bytes, notes: list[str]) -> str:
    text = decode(data)
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        notes.append(f"read the first {MAX_LINES} of {len(lines)} lines "
                     f"(line cap)")
        text = "\n".join(lines[:MAX_LINES])
    return text


def _empty_plan(case_name: str, basis: str, note: str) -> IntentPlan:
    plan = IntentPlan(case_name=case_name[:120],
                      authorization_basis=basis,  # type: ignore[arg-type]
                      extractor="ingest_v1")
    plan.warnings.append(note)
    plan.summary = note
    return plan


def ingest(
    filename: str,
    data: bytes,
    *,
    authorization_basis: str = "training_lab",
    authorization_note: str = "",
    trusted_domains: set[str] | None = None,
    depth: int = 1,
    max_entities: int = 200,
) -> IngestResult:
    """Read one uploaded file into a plan. Never raises."""
    notes: list[str] = []
    name = safe_name(filename)
    size = len(data or b"")

    if size > MAX_BYTES:
        notes.append(
            f"file is {size / 1_048_576:.1f} MB; only the first "
            f"{MAX_BYTES // 1_048_576} MB were read (size cap). Anything past "
            f"that point was not looked at, and is not a clean result."
        )
        data = data[:MAX_BYTES]

    if not size:
        return IngestResult(
            kind=Kind.TEXT, filename=name, size=0,
            plan=_empty_plan(f"Upload: {name}", authorization_basis,
                             "The file is empty, so there was nothing to read."),
            notes=["the file is empty"],
        )

    if data[:2] == b"\x1f\x8b":
        try:
            import gzip
            import io
            inflated = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_BYTES + 1)
            notes.append(
                "decompressed a gzip wrapper before sniffing the inner file"
            )
            data = inflated[:MAX_BYTES]
            size = len(data)
        except Exception:
            notes.append("file starts like gzip but could not be inflated")

    kind = sniff(filename, data)

    try:
        return _dispatch(kind, name, data, size, notes,
                         authorization_basis=authorization_basis,
                         authorization_note=authorization_note,
                         trusted_domains=trusted_domains,
                         depth=depth, max_entities=max_entities)
    except Exception as exc:  # noqa: BLE001 - an upload must not be able to 500
        logger.exception("ingest failed for %s (%s)", name, kind)
        notes.append(f"this file could not be read as {kind.value} ({exc})")
        return IngestResult(
            kind=kind, filename=name, size=size, notes=notes,
            plan=_empty_plan(
                f"Upload: {name}", authorization_basis,
                "Umbra could not read this file. Nothing was extracted, which "
                "is not the same as the file containing nothing."),
        )


def _dispatch(kind: Kind, name: str, data: bytes, size: int, notes: list[str],
              *, authorization_basis: str, authorization_note: str,
              trusted_domains: set[str] | None, depth: int,
              max_entities: int) -> IngestResult:
    from umbra.ingest.entities import (
        csv_values,
        json_values,
        plan_from_text,
    )

    findings: list[Finding] = []
    metadata: dict = {}
    email_parse: ParsedEmail | None = None

    # Notes that quote the file. They are worth showing the analyst who just
    # uploaded it — "I dropped row 1, here is what was in it" — but the plan is
    # persisted as a case and rendered on a page, so they stop at the screen.
    # Same split as `umbra.email.plan._origin_line`.
    content_notes: list[str] = []

    if kind is Kind.EMAIL:
        from umbra.email.plan import analyze

        # One pass. `analyze` exists so the findings and the plan come out of a
        # single parse — asking for them separately made every upload parse and
        # judge the message twice.
        parsed, findings, plan = analyze(
            decode(data), trusted_domains=trusted_domains,
            authorization_basis=authorization_basis,
            authorization_note=authorization_note, depth=depth,
            max_entities=max_entities)
        email_parse = parsed
        plan.case_name = f"Email: {name}"[:120]
        metadata = {
            "from": parsed.from_addr,
            "subject": parsed.subject,
            "date": parsed.date.isoformat() if parsed.date else None,
            "hops": len(parsed.hops),
            "origin_ip": parsed.origin_ip,
            "origin_note": parsed.origin_note,
            "boundary_basis": parsed.boundary_basis,
        }

    elif kind in TEXT_KINDS:
        text = _read_text(data, notes)
        if kind is Kind.CSV:
            text, extra = csv_values(text)
            content_notes.extend(extra)
        elif kind is Kind.JSON:
            text, extra = json_values(text)
            content_notes.extend(extra)
        plan = plan_from_text(
            text, case_name=f"Upload: {name}",
            authorization_basis=authorization_basis,
            authorization_note=authorization_note,
            depth=depth, max_entities=max_entities)
        plan.extractor = f"ingest_{kind.value}_v1"

    elif kind in META_KINDS:
        from umbra.ingest.metadata import read_metadata

        metadata, meta_seeds, meta_notes = read_metadata(kind, data)
        notes.extend(meta_notes)
        plan = IntentPlan(
            case_name=f"Upload: {name}"[:120],
            authorization_basis=authorization_basis,  # type: ignore[arg-type]
            authorization_note=authorization_note,
            seeds=meta_seeds,
            depth=depth, max_entities=max_entities,
            extractor=f"ingest_{kind.value}_v1",
        )
        plan.collectors = select_collectors(plan.seeds, plan.flags)
        armed = [s for s in plan.seeds if s.include]
        plan.summary = (
            f"{len(metadata)} metadata field(s) read; {len(armed)} of "
            f"{len(plan.seeds)} identifier(s) selected to run."
        )
        if not plan.seeds:
            plan.warnings.append(
                "No identifiers were found in this file's metadata. That may "
                "mean the metadata was stripped before you received it, which "
                "is itself worth knowing — it is not a statement about the "
                "file's contents."
            )

    else:
        plan = _empty_plan(
            f"Upload: {name}", authorization_basis,
            "Umbra does not have a reader for this file type, so nothing was "
            "extracted. Supported: email, txt/log, csv/tsv, json/ndjson, "
            "html/xml/yaml, ics/vcf, images (jpeg/png/gif/tiff/webp/bmp), "
            "PDF, Office (docx/xlsx/pptx) and OpenDocument.")
        notes.append(f"no reader for {kind.value} files")

    plan.raw_intent = (f"Uploaded {kind.value} file {name} ({size} bytes)")[:280]
    plan = _cap_seeds(plan, notes)
    # Only the structural notes persist — a cap or an unreadable section changes
    # how the result should be read, so it has to travel with the case.
    plan.warnings.extend(n for n in notes if n not in plan.warnings)

    return IngestResult(kind=kind, filename=name, size=size, plan=plan,
                        findings=findings, metadata=metadata,
                        notes=notes + content_notes, parsed=email_parse)
