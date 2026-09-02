"""Metadata out of the file types it is easy to get metadata from.

Carl asked for the upload button to cover "other file types that it's easy to
get metadata from for analysis". These three are that: a JPEG's EXIF block is a
TIFF directory, an Office document is a zip with two XML files in it, and a
PDF's Info dictionary is a handful of `/Key (value)` pairs. All three are
standard library work — Pillow, python-docx and pypdf would each be a
dependency added to a security tool for the sake of a few dozen bytes.

The fixtures are built here rather than committed, byte by byte, so what each
test exercises is visible in the test.

The recurring rule shows up again and lands harder here than anywhere else in
the codebase: **stripped metadata and absent metadata are different facts**. A
PDF whose Info dictionary sits inside a compressed object stream must not
report "no author", because the author may well be there. So must a JPEG with
no EXIF block — that absence is usually a re-save or a deliberate scrub, and
saying so is more useful than an empty table.
"""
from __future__ import annotations

import io
import struct
import warnings
import zipfile
import zlib

import pytest

warnings.filterwarnings("ignore")

from umbra.core.models import EntityType  # noqa: E402
from umbra.ingest import ingest  # noqa: E402
from umbra.ingest.detect import Kind  # noqa: E402
from umbra.ingest.metadata import read_image, read_ooxml, read_pdf  # noqa: E402


# --- fixture builders ------------------------------------------------------

def _ascii(text: str) -> tuple[int, int, bytes]:
    raw = text.encode() + b"\x00"
    return 2, len(raw), raw


def _long(value: int) -> tuple[int, int, bytes]:
    return 4, 1, struct.pack("<I", value)


def _rational(*pairs) -> tuple[int, int, bytes]:
    raw = b"".join(struct.pack("<II", n, d) for n, d in pairs)
    return 5, len(pairs), raw


def _pack_ifd(tags: dict, data_offset: int) -> tuple[bytes, bytes, int]:
    """One IFD plus its overflow pool. Values >4 bytes live in the pool."""
    body = struct.pack("<H", len(tags))
    pool = b""
    cursor = data_offset
    for tag in sorted(tags):
        kind, count, payload = tags[tag]
        if len(payload) <= 4:
            value = payload.ljust(4, b"\x00")
        else:
            value = struct.pack("<I", cursor)
            pool += payload
            cursor += len(payload)
        body += struct.pack("<HHI", tag, kind, count) + value
    return body + struct.pack("<I", 0), pool, cursor


def build_jpeg_with_exif(make="Fairphone", model="FP4", software="Umbra Test",
                         artist="Dana Whitfield <dana@studio.example>",
                         gps=True) -> bytes:
    """A minimal JPEG whose APP1 segment carries a real TIFF/EXIF directory."""
    gps_tags = {
        1: _ascii("N"),
        2: _rational((37, 1), (46, 1), (2964, 100)),      # 37.7749
        3: _ascii("W"),
        4: _rational((122, 1), (25, 1), (984, 100)),      # -122.4194
        29: _ascii("2026:08:19"),
    }
    exif_tags = {
        0x9003: _ascii("2026:08:19 10:22:31"),
        0xA430: _ascii("Dana Whitfield"),
        0xA434: _ascii("FP4 wide"),
    }
    ifd0_tags = {
        0x010F: _ascii(make),
        0x0110: _ascii(model),
        0x0131: _ascii(software),
        0x013B: _ascii(artist),
    }

    # Sizes first, because IFD0 has to hold pointers to the other two.
    size0 = 2 + 12 * (len(ifd0_tags) + (2 if gps else 1)) + 4
    size_exif = 2 + 12 * len(exif_tags) + 4
    size_gps = 2 + 12 * len(gps_tags) + 4

    exif_at = 8 + size0
    gps_at = exif_at + size_exif
    pool_at = gps_at + (size_gps if gps else 0)

    ifd0_tags[0x8769] = _long(exif_at)
    if gps:
        ifd0_tags[0x8825] = _long(gps_at)

    ifd0, pool0, cursor = _pack_ifd(ifd0_tags, pool_at)
    exif, pool1, cursor = _pack_ifd(exif_tags, cursor)
    tiff = b"II" + struct.pack("<HI", 42, 8) + ifd0 + exif
    if gps:
        gps_ifd, pool2, cursor = _pack_ifd(gps_tags, cursor)
        tiff += gps_ifd
    else:
        pool2 = b""
    tiff += pool0 + pool1 + pool2

    app1 = b"Exif\x00\x00" + tiff
    return (b"\xff\xd8"
            + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + b"\xff\xda\x00\x02"          # start of scan
            + b"\x00" * 8 + b"\xff\xd9")


def build_jpeg_stripped() -> bytes:
    return b"\xff\xd8" + b"\xff\xda\x00\x02" + b"\x00" * 16 + b"\xff\xd9"


CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:creator>Dana Whitfield</dc:creator>
  <cp:lastModifiedBy>m.ortiz@contractor.example</cp:lastModifiedBy>
  <dc:title>Q3 network plan</dc:title>
  <dcterms:created>2026-07-02T09:11:00Z</dcterms:created>
  <cp:revision>14</cp:revision>
</cp:coreProperties>"""

APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>Northwind Logistics</Company>
  <TotalTime>412</TotalTime>
</Properties>"""

RELS_XML = ('<?xml version="1.0"?><Relationships>'
            '<Relationship Id="rId4" Target="https://payload.example/track.png"'
            ' TargetMode="External"/></Relationships>')


def build_docx(core=CORE_XML, app=APP_XML, rels=RELS_XML) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        if core:
            archive.writestr("docProps/core.xml", core)
        if app:
            archive.writestr("docProps/app.xml", app)
        if rels:
            archive.writestr("word/_rels/document.xml.rels", rels)
    return buf.getvalue()


PLAIN_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Title (Q3 network plan) /Author (Dana Whitfield) "
    b"/Producer (LibreOffice 7.4.2) /Creator (Writer) "
    b"/CreationDate (D:20260702091100Z) >>\nendobj\n"
    b"trailer\n<< /Info 1 0 R /Root 2 0 R >>\n%%EOF\n"
)


def build_pdf_compressed() -> bytes:
    inner = (b"<< /Title (Compressed title) /Author (Hidden Author) "
             b"/Producer (Ghostscript 10.02) >>")
    blob = zlib.compress(inner)
    return (b"%PDF-1.5\n5 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length "
            + str(len(blob)).encode() + b" >>\nstream\n" + blob
            + b"\nendstream\nendobj\ntrailer\n<< /Root 2 0 R >>\n%%EOF\n")


def build_pdf_opaque() -> bytes:
    """Compressed streams we cannot inflate — the honest-limits case."""
    return (b"%PDF-1.7\n7 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\n"
            b"stream\n" + bytes([0x00, 0xFF] * 60) + b"\nendstream\nendobj\n"
            b"%%EOF\n")


# --- EXIF ------------------------------------------------------------------

@pytest.fixture
def photo():
    return build_jpeg_with_exif()


def test_a_jpeg_with_exif_is_detected_as_an_image(photo):
    result = ingest("holiday.jpg", photo)
    assert result.kind is Kind.IMAGE


def test_the_camera_is_read(photo):
    data = read_image(photo, [])
    assert data["Make"] == "Fairphone"
    assert data["Model"] == "FP4"


def test_the_software_that_wrote_it_is_read(photo):
    assert read_image(photo, [])["Software"] == "Umbra Test"


def test_the_exif_sub_directory_is_followed(photo):
    """DateTimeOriginal and the lens live in a nested IFD, not IFD0. A reader
    that stops at IFD0 silently loses the most useful half."""
    data = read_image(photo, [])
    assert data["DateTimeOriginal"].startswith("2026:08:19")
    assert data["LensModel"] == "FP4 wide"


def test_gps_coordinates_become_a_decimal_position(photo):
    """The single most consequential thing in an image, and the reason the
    reader exists."""
    position = read_image(photo, [])["GPSPosition"]
    latitude, longitude = position.split(",")
    assert latitude.startswith("37.77")
    assert longitude.startswith("-122.41")


def test_the_southern_and_western_hemispheres_are_signed(photo):
    assert read_image(photo, [])["GPSPosition"].split(",")[1].startswith("-")


def test_the_position_becomes_a_seed_that_runs(photo):
    result = ingest("holiday.jpg", photo)
    location = next(s for s in result.plan.seeds
                    if s.type is EntityType.LOCATION)
    assert location.include is True
    assert "37.77" in location.value


def test_an_address_in_the_artist_field_is_extracted(photo):
    result = ingest("holiday.jpg", photo)
    values = {s.value for s in result.plan.seeds}
    assert "dana@studio.example" in values
    assert "studio.example" in values


def test_a_persons_name_is_shown_but_not_armed(photo):
    """A name is a weak identifier, and searching one is a search about a
    person. Same line the intent extractor already draws."""
    result = ingest("holiday.jpg", photo)
    person = next(s for s in result.plan.seeds if s.type is EntityType.PERSON)
    assert person.include is False
    assert person.notes


def test_the_camera_becomes_a_technology_seed(photo):
    result = ingest("holiday.jpg", photo)
    assert any(s.type is EntityType.TECHNOLOGY for s in result.plan.seeds)


def test_a_stripped_jpeg_says_so_rather_than_reporting_nothing():
    """"No EXIF" is a finding about the file's history, not an empty result.
    Phones write EXIF; its absence means a re-save or a scrub."""
    notes: list[str] = []
    assert read_image(build_jpeg_stripped(), notes) == {}
    assert notes
    assert "scrub" in notes[0] or "re-saved" in notes[0]


def test_a_truncated_jpeg_does_not_raise():
    photo = build_jpeg_with_exif()
    for cut in (4, 12, 40, 100, len(photo) - 3):
        read_image(photo[:cut], [])


def test_a_lying_exif_offset_does_not_raise():
    """Every offset in a TIFF directory comes from the file itself."""
    photo = bytearray(build_jpeg_with_exif())
    for index in range(20, min(len(photo) - 4, 160), 7):
        broken = bytearray(photo)
        broken[index:index + 4] = struct.pack("<I", 0xFFFFFF00)
        read_image(bytes(broken), [])


# --- OOXML -----------------------------------------------------------------

def test_a_docx_is_detected():
    assert ingest("plan.docx", build_docx()).kind is Kind.OOXML


def test_the_author_and_editor_are_read():
    data = read_ooxml(build_docx(), [])
    assert data["Author"] == "Dana Whitfield"
    assert data["LastModifiedBy"] == "m.ortiz@contractor.example"


def test_the_company_is_read():
    assert read_ooxml(build_docx(), [])["Company"] == "Northwind Logistics"


def test_the_editing_time_is_read():
    """412 minutes on a two-page memo is the kind of thing an analyst notices."""
    assert read_ooxml(build_docx(), [])["EditingMinutes"] == "412"


def test_an_editor_address_becomes_an_armed_seed():
    result = ingest("plan.docx", build_docx())
    values = {s.value for s in result.plan.seeds if s.include}
    assert "m.ortiz@contractor.example" in values
    assert "contractor.example" in values


def test_external_links_are_extracted():
    """A remote image in a document is how a template injection or a tracking
    pixel arrives."""
    data = read_ooxml(build_docx(), [])
    assert any("payload.example" in link for link in data["ExternalLinks"])


def test_the_link_host_becomes_a_seed():
    result = ingest("plan.docx", build_docx())
    assert "payload.example" in {s.value for s in result.plan.seeds}


def test_a_document_with_no_docprops_says_so():
    notes: list[str] = []
    read_ooxml(build_docx(core="", app="", rels=""), notes)
    assert notes
    assert "stripped" in " ".join(notes)


def test_a_corrupt_zip_does_not_raise():
    notes: list[str] = []
    read_ooxml(b"PK\x03\x04" + b"\x00" * 500, notes)
    assert notes


def test_malformed_xml_inside_a_valid_zip_does_not_raise():
    notes: list[str] = []
    read_ooxml(build_docx(core="<not closed"), notes)
    assert notes


# --- PDF -------------------------------------------------------------------

def test_a_pdf_is_detected():
    assert ingest("plan.pdf", PLAIN_PDF).kind is Kind.PDF


def test_the_info_dictionary_is_read():
    data = read_pdf(PLAIN_PDF, [])
    assert data["Author"] == "Dana Whitfield"
    assert data["Producer"] == "LibreOffice 7.4.2"


def test_metadata_inside_a_compressed_object_stream_is_reached():
    """Modern producers put the Info dictionary inside a Flate stream. Not
    inflating it is the difference between "no author" and "no author
    recorded"."""
    data = read_pdf(build_pdf_compressed(), [])
    assert data["Author"] == "Hidden Author"
    assert data["Producer"] == "Ghostscript 10.02"


def test_a_pdf_we_cannot_inflate_admits_it():
    """The honest-limits case. Reporting an empty table here would state as
    fact something we did not check."""
    notes: list[str] = []
    assert read_pdf(build_pdf_opaque(), notes) == {}
    assert notes
    assert "unread rather than absent" in notes[0]


def test_an_xmp_packet_is_read():
    pdf = (b"%PDF-1.6\n<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
           b"<dc:title>XMP title</dc:title>"
           b"<xmp:CreatorTool>Acrobat Distiller</xmp:CreatorTool>"
           b"</x:xmpmeta>\n%%EOF")
    data = read_pdf(pdf, [])
    assert data["Title"] == "XMP title"
    assert data["Creator"] == "Acrobat Distiller"


def test_a_hex_string_value_is_decoded():
    pdf = b"%PDF-1.4\n<< /Author <44616e61> >>\n%%EOF"
    assert read_pdf(pdf, [])["Author"] == "Dana"


def test_the_producer_becomes_a_technology_seed():
    result = ingest("plan.pdf", PLAIN_PDF)
    tech = {s.value for s in result.plan.seeds
            if s.type is EntityType.TECHNOLOGY}
    assert any("LibreOffice" in t for t in tech)


def test_a_truncated_pdf_does_not_raise():
    for cut in (5, 20, 60, len(PLAIN_PDF) - 2):
        read_pdf(PLAIN_PDF[:cut], [])


def test_a_decompression_bomb_stops_at_the_cap():
    """A stream that inflates to a gigabyte must not be inflated to a gigabyte.

    Asserted by putting the metadata *past* the cap: if the reader finds it, it
    inflated further than it promised to, and a budget checked after the fact is
    not a budget.
    """
    from umbra.ingest.metadata import MAX_PDF_INFLATED

    payload = b"A" * (MAX_PDF_INFLATED + 4096) + b"/Author (Past The Cap)"
    blob = zlib.compress(payload)
    pdf = b"%PDF-1.5\nstream\n" + blob + b"\nendstream\n%%EOF"
    assert "Author" not in read_pdf(pdf, [])


# --- across all three ------------------------------------------------------

def test_metadata_files_never_carry_their_own_bytes_into_the_plan():
    for name, data in (("holiday.jpg", build_jpeg_with_exif()),
                       ("plan.docx", build_docx()),
                       ("plan.pdf", PLAIN_PDF)):
        result = ingest(name, data)
        assert len(result.plan.model_dump_json()) < 20_000


def test_the_metadata_is_available_for_display():
    result = ingest("plan.docx", build_docx())
    assert result.metadata.get("Author") == "Dana Whitfield"


def test_a_file_with_no_metadata_does_not_look_like_a_clean_result():
    result = ingest("bare.jpg", build_jpeg_stripped())
    assert result.plan.warnings
    joined = " ".join(result.plan.warnings).lower()
    assert "not" in joined
