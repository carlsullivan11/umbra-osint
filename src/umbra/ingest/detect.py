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
    (b"RIFF", "riff"),
)

_MAIL_HEADER_RE = re.compile(
    r"(?im)^(Received|From|To|Cc|Subject|Date|Message-ID|Return-Path|Reply-To|"
    r"DKIM-Signature|Authentication-Results|Delivered-To|MIME-Version|Sender|"
    r"X-Originating-IP|List-Unsubscribe|X-Mailer|Content-Type)\s*:",
)

# One `From:` line is a fragment; several distinct headers is a message.
_MIN_MAIL_HEADERS = 3

_MAIL_EXTENSIONS = (".eml", ".email", ".mbox", ".mail", ".msg.txt", ".hdr")
_OOXML_MEMBERS = (b"[Content_Types].xml", b"word/", b"xl/", b"ppt/", b"docProps/")


class Kind(str, Enum):
    EMAIL = "email"
    TEXT = "text"
    CSV = "csv"
    JSON = "json"
    IMAGE = "image"
    OOXML = "ooxml"
    PDF = "pdf"
    UNKNOWN = "unknown"


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


# Windows "Save As" writes UTF-16 with one of these in front of it.
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
    # Headers come first. If the matches only appear far into the file it is
    # probably a log or a document quoting mail, not a message.
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
        if magic in {"jpeg", "png", "tiff", "gif"}:
            return Kind.IMAGE
        if magic == "zip":
            head = data[:8192]
            return Kind.OOXML if any(m in head for m in _OOXML_MEMBERS) else Kind.UNKNOWN
        if magic == "riff":
            return Kind.UNKNOWN

        # A UTF-16 byte-order mark is positive evidence of text, so it settles
        # the question before the byte-level heuristic gets to mistake the NULs
        # for binary content.
        wide = data[:2] in _UTF16_BOMS
        if not wide and _looks_binary(data):
            return Kind.UNKNOWN

        text = decode(data)
        if not text.strip():
            return Kind.TEXT

        if looks_like_mail(text):
            return Kind.EMAIL

        stripped = text.lstrip()
        if stripped[:1] in "{[":
            try:
                json.loads(text)
                return Kind.JSON
            except (ValueError, RecursionError):
                pass  # a broken JSON file is still text worth reading

        # The name alone is only a claim, but the name *plus* real mail headers
        # is enough. This matters for privacy, not tidiness: a clipped fragment
        # with just `From:` and `To:` misses the three-header bar, and the
        # generic text extractor that catches it has no idea which address is
        # the sender — so it arms the recipient's own address and their
        # employer's mail domain. The mail reader knows the difference.
        if name.endswith(_MAIL_EXTENSIONS) and looks_like_mail(text, min_headers=2):
            return Kind.EMAIL

        if name.endswith((".csv", ".tsv")) or _looks_like_csv(text):
            return Kind.CSV

        # The extension gets the last word only when the content was ambiguous —
        # an .eml with no recognisable headers is a text file, and calling it
        # mail would produce an empty parse that reads as "nothing wrong here".
        if name.endswith(_MAIL_EXTENSIONS):
            return Kind.TEXT

        if name.endswith(".json"):
            return Kind.JSON

        return Kind.TEXT
    except Exception:  # noqa: BLE001 - detection must never be the thing that fails
        return Kind.UNKNOWN
