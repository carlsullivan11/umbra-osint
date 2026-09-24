"""What kind of file is this, judged from the bytes.

The extension is a hint from whoever named the file, which on an upload
endpoint means it is a hint from a stranger. A PDF called `notes.txt` is a PDF,
and a `.eml` containing nothing but IP addresses should go to the list reader
rather than through a header parser that will find nothing and report an empty
result — which would read as "this message is clean".

So: magic bytes first, structure second, extension only as a tie-breaker.
"""
from __future__ import annotations

import json
import re
from enum import Enum

# Magic numbers, longest first so the more specific match wins.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "pdf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"PK\x03\x04", "zip"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"\x1f\x8b", "gzip"),
    (b"RIFF", "riff"),
    (b"BM", "bmp"),
)

_MAIL_HEADER_RE = re.compile(
    r"(?im)^(Received|From|To|Cc|Subject|Date|Message-ID|Return-Path|Reply-To|"
    r"DKIM-Signature|Authentication-Results|Delivered-To|MIME-Version|Sender|"
    r"X-Originating-IP|List-Unsubscribe|X-Mailer|Content-Type)\s*:",
)

_MIN_MAIL_HEADERS = 3

_MAIL_EXTENSIONS = (".eml", ".email", ".mbox", ".mail", ".msg.txt", ".hdr")
_OOXML_MEMBERS = (b"[Content_Types].xml", b"word/", b"xl/", b"ppt/", b"docProps/")


class Kind(str, Enum):
    EMAIL = "email"
    TEXT = "text"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    XML = "xml"
    YAML = "yaml"
    ICS = "ics"
    VCF = "vcf"
    IMAGE = "image"
    OOXML = "ooxml"
    ODF = "odf"
    PDF = "pdf"
    UNKNOWN = "unknown"


TEXT_KINDS = {
    Kind.TEXT, Kind.CSV, Kind.JSON, Kind.HTML, Kind.XML,
    Kind.YAML, Kind.ICS, Kind.VCF,
}
META_KINDS = {Kind.IMAGE, Kind.OOXML, Kind.ODF, Kind.PDF}


def decode(data: bytes) -> str:
    """Bytes → text, without ever raising.

    Mail headers are frequently latin-1 in practice regardless of what they
    declare, and a decode error on an upload path is an outage, not a finding.
    """
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        return text.replace("\x00", "")
    return data.decode("utf-8", errors="replace").replace("\x00", "")


def _magic(data: bytes) -> str | None:
    head = data[:64]
    for signature, name in _MAGIC:
        if head.startswith(signature):
            return name
    return None


_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def _looks_binary(data: bytes) -> bool:
    """Byte-level heuristic — deliberately run *after* the BOM check in `sniff`.

    In UTF-16 every other byte of ASCII text is a NUL, so this counts a
    perfectly ordinary saved message as three-quarters unprintable and calls it
    binary. That turned a Windows-exported `.eml` into "no reader for this file
    type", which is an empty result for a message that parses fine.
    """
    sample = data[:8192]
    if not sample:
        return False
    if b"\x00\x00" in sample:
        return True
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    return printable / len(sample) < 0.75


def looks_like_mail(text: str, min_headers: int = _MIN_MAIL_HEADERS) -> bool:
    """A header block, not merely something with a colon in it."""
    head = text[:20_000]
    names = {m.group(1).lower() for m in _MAIL_HEADER_RE.finditer(head)}
    if len(names) < min_headers:
        return False
    first = _MAIL_HEADER_RE.search(head)
    return bool(first and first.start() < 2000)


def _looks_like_csv(text: str) -> bool:
    lines = [line for line in text.splitlines()[:40] if line.strip()]
    if len(lines) < 2:
        return False
    for delimiter in (",", "\t", ";", "|"):
        counts = [line.count(delimiter) for line in lines]
        if counts[0] >= 1 and len(set(counts)) == 1:
            return True
    return False


def sniff(filename: str, data: bytes) -> Kind:
    """Best guess at what this file is. Never raises."""
    try:
        name = (filename or "").lower().strip()
        magic = _magic(data)

        if magic == "pdf":
            return Kind.PDF
        if magic in {"jpeg", "png", "tiff", "gif", "bmp"}:
            return Kind.IMAGE
        if magic == "riff":
            return Kind.IMAGE if data[8:12] == b"WEBP" else Kind.UNKNOWN
        if magic == "zip":
            head = data[:8192]
            if b"mimetypeapplication/vnd.oasis.opendocument" in head:
                return Kind.ODF
            return Kind.OOXML if any(m in head for m in _OOXML_MEMBERS) else Kind.UNKNOWN
        if magic in {"ole", "gzip"}:
            return Kind.UNKNOWN

        wide = data[:2] in _UTF16_BOMS
        if not wide and _looks_binary(data):
            return Kind.UNKNOWN

        text = decode(data)
        if not text.strip():
            return Kind.TEXT

        if looks_like_mail(text):
            return Kind.EMAIL

        stripped = text.lstrip()
        low = stripped[:64].lower()
        if low.startswith(("<!doctype html", "<html")) or name.endswith((".html", ".htm")):
            if low.startswith(("<!doctype html", "<html")) or name.endswith((".html", ".htm")):
                return Kind.HTML
        if stripped.startswith("<?xml") or name.endswith(".xml") or name.endswith(".svg"):
            return Kind.XML
        if stripped.upper().startswith("BEGIN:VCALENDAR") or name.endswith(".ics"):
            return Kind.ICS
        if stripped.upper().startswith("BEGIN:VCARD") or name.endswith((".vcf", ".vcard")):
            return Kind.VCF

        if stripped[:1] in "{[":
            try:
                json.loads(text)
                return Kind.JSON
            except (ValueError, RecursionError):
                pass

        if name.endswith(_MAIL_EXTENSIONS) and looks_like_mail(text, min_headers=2):
            return Kind.EMAIL

        if name.endswith((".csv", ".tsv")) or _looks_like_csv(text):
            return Kind.CSV

        if name.endswith(_MAIL_EXTENSIONS):
            return Kind.TEXT

        if name.endswith(".json") or name.endswith(".ndjson") or name.endswith(".jsonl"):
            return Kind.JSON

        if name.endswith((".yml", ".yaml")):
            return Kind.YAML

        return Kind.TEXT
    except Exception:  # noqa: BLE001 - detection must never be the thing that fails
        return Kind.UNKNOWN
