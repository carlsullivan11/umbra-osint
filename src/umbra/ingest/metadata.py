"""Document and image metadata — the "easy to get metadata from" file types.

Everything here is standard library. Pillow, pypdf and python-docx would each
do more, and each would be a dependency added to a security tool for the sake
of reading a few dozen bytes of header. EXIF is a TIFF IFD, an Office document
is a zip with two XML files in it, and a PDF's Info dictionary is usually a
handful of `/Key (value)` pairs — none of that needs a library.

**The honesty rule applies especially here.** Absent metadata is not the same
as absent metadata *fields*: a PDF whose Info dictionary sits inside a
compressed object stream that we could not decompress must say so, or "no
author" reads as a fact when it is a limitation. Every reader below reports
what it could not reach.

Nothing in this module executes, renders, or resolves anything from the file.
No network. No temporary files.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from xml.etree import ElementTree

from umbra.core.models import EntityType
from umbra.ingest.detect import Kind
from umbra.intent.schema import IntentSeed

# Bounds. Uploads are hostile input and these readers walk offsets that the
# file itself supplies.
MAX_IFD_ENTRIES = 400
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_PDF_STREAMS = 80
MAX_PDF_INFLATED = 4 * 1024 * 1024
MAX_VALUE_LEN = 500

_EMAIL_RE = re.compile(r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"')]{4,400}")

# --- EXIF -----------------------------------------------------------------

_TIFF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime",
    0x013B: "Artist", 0x8298: "Copyright", 0x010E: "ImageDescription",
    0x00FE: None, 0x8769: "_exif_ifd", 0x8825: "_gps_ifd",
}
_EXIF_TAGS = {
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x927C: "MakerNote", 0x9286: "UserComment", 0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber", 0xA433: "LensMake", 0xA434: "LensModel",
    0xA420: "ImageUniqueID", 0x001D: "GPSDateStamp",
}
_GPS_TAGS = {
    1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef",
    4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude",
    29: "GPSDateStamp", 27: "GPSProcessingMethod",
}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
              11: 4, 12: 8}


def _read_ifd(buf: bytes, offset: int, endian: str,
              names: dict) -> dict[str, object]:
    """One TIFF image file directory. Bounds-checked against a hostile file."""
    out: dict[str, object] = {}
    if offset <= 0 or offset + 2 > len(buf):
        return out
    (count,) = struct.unpack(endian + "H", buf[offset:offset + 2])
    count = min(count, MAX_IFD_ENTRIES)
    for i in range(count):
        entry = offset + 2 + i * 12
        if entry + 12 > len(buf):
            break
        tag, kind, length = struct.unpack(endian + "HHI", buf[entry:entry + 8])
        name = names.get(tag)
        if name is None:
            continue
        size = _TYPE_SIZE.get(kind, 0) * length
        if size <= 0 or size > 65536:
            continue
        if size <= 4:
            raw = buf[entry + 8:entry + 8 + size]
        else:
            (pointer,) = struct.unpack(endian + "I", buf[entry + 8:entry + 12])
            if pointer + size > len(buf):
                continue
            raw = buf[pointer:pointer + size]

        if kind == 2:  # ASCII
            out[name] = raw.split(b"\x00")[0].decode("utf-8", "replace")[:MAX_VALUE_LEN]
        elif kind in (5, 10):  # RATIONAL
            values = []
            for j in range(length):
                chunk = raw[j * 8:(j + 1) * 8]
                if len(chunk) < 8:
                    break
                num, den = struct.unpack(endian + ("ii" if kind == 10 else "II"),
                                         chunk)
                values.append(num / den if den else 0.0)
            out[name] = values
        elif kind in (3, 4, 8, 9):
            fmt = {3: "H", 4: "I", 8: "h", 9: "i"}[kind]
            try:
                out[name] = list(struct.unpack(
                    endian + fmt * length, raw[:_TYPE_SIZE[kind] * length]))
            except struct.error:
                continue
        elif kind == 7:  # UNDEFINED — UserComment and friends
            out[name] = raw[:MAX_VALUE_LEN].decode("utf-8", "replace").strip("\x00")
    return out


def _dms(values, ref: str | None) -> float | None:
    """Degrees/minutes/seconds → a signed decimal degree."""
    if not isinstance(values, list) or len(values) < 3:
        return None
    try:
        degrees = values[0] + values[1] / 60 + values[2] / 3600
    except (TypeError, ZeroDivisionError):
        return None
    if (ref or "").upper().startswith(("S", "W")):
        degrees = -degrees
    return round(degrees, 6)


def _tiff(buf: bytes, notes: list[str]) -> dict:
    if len(buf) < 8:
        return {}
    endian = "<" if buf[:2] == b"II" else ">" if buf[:2] == b"MM" else None
    if endian is None:
        return {}
    magic, first = struct.unpack(endian + "HI", buf[2:8])
    if magic != 42:
        return {}

    out: dict = {}
    ifd0 = _read_ifd(buf, first, endian, _TIFF_TAGS)
    for key, value in ifd0.items():
        if not key.startswith("_"):
            out[key] = value

    pointer = ifd0.get("_exif_ifd")
    if isinstance(pointer, list) and pointer:
        out.update({k: v for k, v in
                    _read_ifd(buf, int(pointer[0]), endian, _EXIF_TAGS).items()
                    if not k.startswith("_")})

    pointer = ifd0.get("_gps_ifd")
    if isinstance(pointer, list) and pointer:
        gps = _read_ifd(buf, int(pointer[0]), endian, _GPS_TAGS)
        lat = _dms(gps.get("GPSLatitude"), str(gps.get("GPSLatitudeRef") or ""))
        lon = _dms(gps.get("GPSLongitude"), str(gps.get("GPSLongitudeRef") or ""))
        if lat is not None and lon is not None:
            out["GPSPosition"] = f"{lat},{lon}"
        for key in ("GPSDateStamp", "GPSAltitude"):
            if key in gps:
                out[key] = gps[key]
    return out


def _jpeg_exif(data: bytes, notes: list[str]) -> dict:
    """Walk JPEG segments for the APP1 that holds EXIF."""
    i = 2
    stripped = True
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xDA:  # start of scan — headers are done
            break
        (length,) = struct.unpack(">H", data[i + 2:i + 4])
        segment = data[i + 4:i + 2 + length]
        if marker == 0xE1 and segment[:6] == b"Exif\x00\x00":
            stripped = False
            return _tiff(segment[6:], notes)
        i += 2 + max(length, 2)
    if stripped:
        notes.append(
            "this JPEG carries no EXIF block. Cameras and phones write one, so "
            "its absence usually means the image was re-saved or deliberately "
            "scrubbed — it does not mean the picture was never geotagged."
        )
    return {}


def _png_text(data: bytes, notes: list[str]) -> dict:
    """PNG tEXt/iTXt chunks. Modest, but Software and Comment show up here."""
    out: dict = {}
    i = 8
    while i + 8 <= len(data) and len(out) < 40:
        try:
            (length,) = struct.unpack(">I", data[i:i + 4])
        except struct.error:
            break
        kind = data[i + 4:i + 8]
        if length > len(data):
            break
        body = data[i + 8:i + 8 + length]
        if kind in (b"tEXt", b"iTXt"):
            parts = body.split(b"\x00", 1)
            if len(parts) == 2:
                key = parts[0].decode("latin-1", "replace")[:60]
                out[key] = parts[1].decode("utf-8", "replace").strip("\x00")[:MAX_VALUE_LEN]
        elif kind == b"IDAT":
            break
        i += 12 + length
    if not out:
        notes.append("this PNG carries no text metadata chunks")
    return out


def read_image(data: bytes, notes: list[str]) -> dict:
    if data[:3] == b"\xff\xd8\xff":
        return _jpeg_exif(data, notes)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _png_text(data, notes)
    if data[:2] in (b"II", b"MM"):
        return _tiff(data, notes)
    notes.append("image format recognised but no metadata container was found")
    return {}


# --- OOXML ----------------------------------------------------------------

_CORE_FIELDS = {
    "creator": "Author", "lastModifiedBy": "LastModifiedBy", "title": "Title",
    "subject": "Subject", "description": "Description", "keywords": "Keywords",
    "category": "Category", "created": "Created", "modified": "Modified",
    "revision": "Revision", "contentStatus": "ContentStatus",
    "lastPrinted": "LastPrinted", "identifier": "Identifier",
}
_APP_FIELDS = {
    "Application": "Application", "Company": "Company", "Manager": "Manager",
    "AppVersion": "AppVersion", "Template": "Template",
    "TotalTime": "EditingMinutes", "Pages": "Pages", "Words": "Words",
    "HyperlinkBase": "HyperlinkBase",
}


def read_ooxml(data: bytes, notes: list[str]) -> dict:
    out: dict = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError, ValueError) as exc:
        notes.append(f"this file starts like a zip but could not be opened ({exc})")
        return out

    names = set(archive.namelist())
    for member, fields in (("docProps/core.xml", _CORE_FIELDS),
                           ("docProps/app.xml", _APP_FIELDS)):
        if member not in names:
            continue
        try:
            info = archive.getinfo(member)
            if info.file_size > MAX_MEMBER_BYTES:
                notes.append(f"{member} is implausibly large; not parsed")
                continue
            blob = archive.read(member)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"could not read {member} ({exc})")
            continue
        try:
            root = ElementTree.fromstring(blob)
        except ElementTree.ParseError as exc:
            notes.append(f"{member} is not valid XML ({exc})")
            continue
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            label = fields.get(tag)
            if label and (node.text or "").strip():
                out[label] = node.text.strip()[:MAX_VALUE_LEN]

    if not out:
        notes.append(
            "this document has no docProps metadata. Office writes it by "
            "default, so an empty one usually means it was stripped or the file "
            "was produced by another tool."
        )
    # Where the document points is often more useful than who wrote it.
    if "word/_rels/document.xml.rels" in names:
        try:
            rels = archive.read("word/_rels/document.xml.rels")[:MAX_MEMBER_BYTES]
            targets = re.findall(rb'Target="(https?://[^"]{4,400})"', rels)
            if targets:
                out["ExternalLinks"] = [t.decode("utf-8", "replace")
                                        for t in targets[:40]]
        except Exception:  # noqa: BLE001
            pass
    return out


# --- PDF ------------------------------------------------------------------

_PDF_KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer",
             "CreationDate", "ModDate", "Company")


def _pdf_string(raw: bytes) -> str:
    text = raw.decode("latin-1", "replace")
    if text.startswith("﻿") or raw[:2] == b"\xfe\xff":
        try:
            text = raw.decode("utf-16-be", "replace").lstrip("﻿")
        except Exception:  # noqa: BLE001
            pass
    return re.sub(r"\\([()\\])", r"\1", text).strip()[:MAX_VALUE_LEN]


def _pdf_scan(blob: bytes, out: dict) -> None:
    for key in _PDF_KEYS:
        if key in out:
            continue
        literal = re.search(rb"/" + key.encode() + rb"\s*\(((?:[^()\\]|\\.)*)\)",
                            blob)
        if literal:
            value = _pdf_string(literal.group(1))
            if value:
                out[key] = value
            continue
        hexed = re.search(rb"/" + key.encode() + rb"\s*<([0-9A-Fa-f\s]{2,2000})>",
                          blob)
        if hexed:
            try:
                raw = bytes.fromhex(re.sub(rb"\s", b"", hexed.group(1)).decode())
                value = _pdf_string(raw)
                if value:
                    out[key] = value
            except ValueError:
                continue


def read_pdf(data: bytes, notes: list[str]) -> dict:
    out: dict = {}
    _pdf_scan(data, out)

    # Modern producers put the Info dictionary inside a compressed object
    # stream, where the plain scan above cannot see it. Inflating the streams is
    # the difference between "no author" and "no author *recorded*".
    inflated_total = 0
    streams = 0
    for match in re.finditer(rb"stream\r?\n", data):
        if streams >= MAX_PDF_STREAMS or inflated_total >= MAX_PDF_INFLATED:
            break
        start = match.end()
        end = data.find(b"endstream", start)
        if end == -1:
            break
        streams += 1
        try:
            # `zlib.decompress` would materialise the whole stream before any
            # counter here could see it, which makes a byte budget checked
            # afterwards no budget at all. A decompressor object with
            # `max_length` stops at the cap instead of allocating past it.
            blob = zlib.decompressobj().decompress(
                data[start:end], MAX_PDF_INFLATED - inflated_total)
        except zlib.error:
            continue
        inflated_total += len(blob)
        _pdf_scan(blob, out)

    xmp = re.search(rb"<x:xmpmeta.{0,200000}?</x:xmpmeta>", data, re.DOTALL)
    if xmp:
        text = xmp.group(0).decode("utf-8", "replace")
        for tag, label in (("dc:creator", "Author"), ("dc:title", "Title"),
                           ("xmp:CreatorTool", "Creator"),
                           ("pdf:Producer", "Producer")):
            found = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", text, re.DOTALL)
            if found and label not in out:
                value = re.sub(r"<[^>]+>", " ", found.group(1)).strip()
                if value:
                    out[label] = value[:MAX_VALUE_LEN]

    if not out:
        compressed = b"/ObjStm" in data or b"/FlateDecode" in data
        notes.append(
            "no document information was found in this PDF."
            + (" It uses compressed object streams that Umbra could not inflate, "
               "so the metadata may be present and unread rather than absent."
               if compressed else
               " The Info dictionary appears genuinely empty.")
        )
    return out


# --- metadata → seeds -----------------------------------------------------

# Which fields become which entity, and whether an analyst has to opt in.
# People and organisations are off by default for the same reason the intent
# extractor defaults name guesses off: a name is a weak identifier and running
# collectors against one is a search about a person.
_TECHNOLOGY_FIELDS = ("Software", "Application", "Producer", "Creator",
                      "Make", "Model", "LensMake", "LensModel", "AppVersion")
_PERSON_FIELDS = ("Artist", "Author", "LastModifiedBy", "CameraOwnerName",
                  "Manager", "Copyright")
_ORG_FIELDS = ("Company",)


def seeds_from_metadata(metadata: dict) -> list[IntentSeed]:
    seeds: list[IntentSeed] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: EntityType, value: str, *, include: bool, confidence: float,
            source: str, notes: str | None = None) -> None:
        value = (value or "").strip()[:300]
        if not value or (kind.value, value.lower()) in seen:
            return
        seen.add((kind.value, value.lower()))
        seeds.append(IntentSeed(type=kind, value=value, confidence=confidence,
                                include=include, source_span=source,
                                notes=notes))

    for field, value in metadata.items():
        text = " ".join(value) if isinstance(value, list) else str(value)
        if not text.strip():
            continue

        for address in _EMAIL_RE.findall(text)[:20]:
            add(EntityType.EMAIL, address, include=True, confidence=0.9,
                source=field, notes=f"an address embedded in {field}")
            domain = address.rsplit("@", 1)[1].lower()
            add(EntityType.DOMAIN, domain, include=True, confidence=0.8,
                source=field, notes=f"the domain of an address in {field}")

        for url in _URL_RE.findall(text)[:20]:
            add(EntityType.URL, url, include=True, confidence=0.85,
                source=field, notes=f"a link recorded in {field}")
            host = url.split("//", 1)[-1].split("/")[0].split(":")[0]
            if host and "." in host:
                add(EntityType.DOMAIN, host.lower(), include=True,
                    confidence=0.8, source=field,
                    notes=f"the host of a link in {field}")

        if field == "GPSPosition":
            add(EntityType.LOCATION, text, include=True, confidence=0.95,
                source="EXIF GPS",
                notes="the coordinates the camera recorded when the picture was "
                      "taken")
        elif field in _TECHNOLOGY_FIELDS:
            add(EntityType.TECHNOLOGY, text, include=True, confidence=0.8,
                source=field, notes=f"the tool named in {field}")
        elif field in _PERSON_FIELDS:
            add(EntityType.PERSON, text, include=False, confidence=0.6,
                source=field,
                notes=f"a name the file records in {field} — off by default "
                      f"because a name is a weak identifier and searching one "
                      f"is a search about a person")
        elif field in _ORG_FIELDS:
            add(EntityType.ORG, text, include=False, confidence=0.6,
                source=field,
                notes=f"the organisation named in {field} — tick it if the "
                      f"organisation is what you are investigating")

    seeds.sort(key=lambda s: (-int(s.include), -s.confidence, s.type.value,
                              s.value))
    return seeds


def read_metadata(kind: Kind, data: bytes) -> tuple[dict, list[IntentSeed], list[str]]:
    """Read one file's metadata. Returns `(fields, seeds, notes)`."""
    notes: list[str] = []
    try:
        if kind is Kind.IMAGE:
            metadata = read_image(data, notes)
        elif kind is Kind.OOXML:
            metadata = read_ooxml(data, notes)
        elif kind is Kind.PDF:
            metadata = read_pdf(data, notes)
        else:
            return {}, [], [f"no metadata reader for {kind.value}"]
    except Exception as exc:  # noqa: BLE001 - hostile input by definition
        return {}, [], [f"metadata could not be read ({type(exc).__name__}: {exc})"]

    return metadata, seeds_from_metadata(metadata), notes
