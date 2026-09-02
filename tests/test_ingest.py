"""One upload button, several kinds of file (Carl, 2026-08-19).

> "this file upload will expand the features to parse a text file of multiple
> IPs or an email file or other file types that it's easy to get metadata from
> for analysis."

The shape that makes that work: every reader, whatever it reads, returns an
`IntentPlan`. From there the confirm page, the narrow-only edit rule, the worker
dispatch and the budgets all already exist, so adding a file type is adding a
reader and nothing else.

Two things are load-bearing throughout.

**The kind is sniffed from content, not from the name.** A file called
`report.txt` that is actually a PDF should be read as a PDF, and a `.eml` full
of nothing but IP addresses should not be forced through a header parser.

**Nothing is trusted about the bytes.** Uploads are the most hostile input this
codebase accepts: size-capped, line-capped, seed-capped, never executed, never
written to disk, and never allowed to raise.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.models import EntityType  # noqa: E402
from umbra.ingest import MAX_BYTES, MAX_LINES, ingest  # noqa: E402
from umbra.ingest.detect import Kind, sniff  # noqa: E402

MAIL_FIXTURES = Path(__file__).parent / "email" / "fixtures"

IP_LIST = """# blocklist export 2026-08-19
185.199.108.153
203.0.113.44
198.51.100.7
23.55.161.10

# with ports, as exports often have
192.0.2.9:8080
"""

MIXED_CSV = """indicator,type,first_seen,note
evil-domain.example,domain,2026-08-01,c2
185.199.108.153,ip,2026-08-02,staging
phish@evil-domain.example,email,2026-08-03,sender
https://evil-domain.example/login,url,2026-08-04,kit
"""

SIEM_JSON = json.dumps({
    "alerts": [
        {"src_ip": "185.199.108.153", "dest": "evil-domain.example",
         "user": "carl@carls-employer.com"},
        {"src_ip": "203.0.113.44", "dest": "another-bad.example"},
    ]
})


def plan_values(result):
    return {s.value for s in result.plan.seeds}


def armed(result):
    return {s.value for s in result.plan.seeds if s.include}


# --- sniffing --------------------------------------------------------------

def test_an_eml_file_is_recognised_as_mail():
    data = (MAIL_FIXTURES / "m365_spoofed.eml").read_bytes()
    assert sniff("message.eml", data) is Kind.EMAIL


def test_carls_dot_email_extension_works():
    """`umbra example.email` is the command he asked for."""
    data = (MAIL_FIXTURES / "google_aligned.eml").read_bytes()
    assert sniff("example.email", data) is Kind.EMAIL


def test_headers_are_recognised_without_any_extension():
    """Pasted-then-saved header blocks rarely have a useful name."""
    data = (MAIL_FIXTURES / "google_aligned.eml").read_bytes()
    assert sniff("untitled", data) is Kind.EMAIL


def test_a_txt_file_of_addresses_is_not_mistaken_for_mail():
    assert sniff("blocklist.txt", IP_LIST.encode()) is Kind.TEXT


def test_a_csv_is_recognised():
    assert sniff("iocs.csv", MIXED_CSV.encode()) is Kind.CSV


def test_json_is_recognised():
    assert sniff("alerts.json", SIEM_JSON.encode()) is Kind.JSON


def test_content_beats_the_extension():
    """A PDF named .txt is a PDF."""
    assert sniff("notes.txt", b"%PDF-1.7\n1 0 obj\n") is Kind.PDF


def test_a_clipped_header_fragment_named_eml_is_read_as_mail():
    """Two headers misses the three-header bar that content sniffing uses, and
    the generic text extractor that would catch it has no idea which address is
    the sender. The filename plus real headers is enough to route it correctly."""
    frag = b"From: security@evil.example\nTo: carl@carls-employer.com\n"
    assert sniff("suspicious.eml", frag) is Kind.EMAIL


def test_that_fragment_still_does_not_arm_the_recipient():
    """The reason the line above matters. Read as plain text, this armed the
    recipient's own address and their employer's mail domain."""
    frag = b"From: security@evil.example\nTo: carl@carls-employer.com\n"
    result = ingest("suspicious.eml", frag)
    assert armed(result) == {"security@evil.example", "evil.example"}
    assert "carl@carls-employer.com" in plan_values(result)


def test_an_ip_list_someone_renamed_to_eml_is_still_a_list():
    """The name is a claim. With no mail headers behind it, it stays a claim —
    otherwise a renamed list parses as an empty message, which reads as "nothing
    wrong with this mail"."""
    assert sniff("blocklist.eml", IP_LIST.encode()) is Kind.TEXT


def test_a_utf16_header_block_is_still_mail():
    """Windows "Save As" writes UTF-16 with a BOM. The byte-level "is this
    binary?" heuristic counts every other byte as an unprintable NUL and calls
    the file binary, so a perfectly ordinary saved message came back as "no
    reader for this file type" — an empty result for a message that parses
    fine."""
    raw = (MAIL_FIXTURES / "google_aligned.eml").read_text().encode("utf-16")
    assert sniff("message.eml", raw) is Kind.EMAIL


def test_a_utf16_indicator_list_is_still_text():
    raw = IP_LIST.encode("utf-16")
    assert sniff("blocklist.txt", raw) is Kind.TEXT


def test_a_utf16_upload_yields_its_entities():
    result = ingest("blocklist.txt", IP_LIST.encode("utf-16"))
    assert "185.199.108.153" in plan_values(result)


def test_unknown_binary_is_named_as_such():
    assert sniff("thing.bin", bytes(range(256)) * 4) is Kind.UNKNOWN


# --- a text file of addresses, which is the case Carl named ---------------

def test_every_address_in_a_list_becomes_a_seed():
    result = ingest("blocklist.txt", IP_LIST.encode())
    for ip in ("185.199.108.153", "203.0.113.44", "198.51.100.7", "23.55.161.10"):
        assert ip in plan_values(result)


def test_addresses_from_a_list_are_armed():
    """The analyst uploaded a list of things to look at. Defaulting them off
    would mean ticking forty boxes before anything happens."""
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert "185.199.108.153" in armed(result)


def test_a_host_port_pair_yields_the_host():
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert "192.0.2.9" in plan_values(result)


def test_comments_do_not_become_entities():
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert not any("blocklist export" in s.value for s in result.plan.seeds)


def test_ip_collectors_are_selected():
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert "rdap_ip" in result.plan.collectors or "asn_cymru" in result.plan.collectors


# --- csv and json ----------------------------------------------------------

def test_a_csv_of_indicators_yields_each_type():
    result = ingest("iocs.csv", MIXED_CSV.encode())
    values = plan_values(result)
    assert "evil-domain.example" in values
    assert "185.199.108.153" in values
    assert "phish@evil-domain.example" in values


def test_csv_column_headers_do_not_become_entities():
    result = ingest("iocs.csv", MIXED_CSV.encode())
    assert "first_seen" not in plan_values(result)


def test_json_values_are_reached_at_any_depth():
    result = ingest("alerts.json", SIEM_JSON.encode())
    values = plan_values(result)
    assert "185.199.108.153" in values
    assert "evil-domain.example" in values


def test_json_keys_do_not_become_entities():
    result = ingest("alerts.json", SIEM_JSON.encode())
    assert "src_ip" not in plan_values(result)


# --- an email file ---------------------------------------------------------

def test_an_email_file_goes_through_the_header_parser():
    data = (MAIL_FIXTURES / "m365_spoofed.eml").read_bytes()
    result = ingest("phish.eml", data)
    assert result.kind is Kind.EMAIL
    assert result.plan.extractor == "email_headers_v1"


def test_the_email_findings_come_back_with_it():
    data = (MAIL_FIXTURES / "m365_spoofed.eml").read_bytes()
    result = ingest("phish.eml", data)
    assert any(f.key == "dkim_unaligned" for f in result.findings)


def test_the_email_privacy_rule_survives_the_upload_path():
    """The recipient is shown and not armed, same as through the CLI."""
    data = (MAIL_FIXTURES / "m365_spoofed.eml").read_bytes()
    result = ingest("phish.eml", data)
    assert "carl@carls-employer.com" in plan_values(result)
    assert "carl@carls-employer.com" not in armed(result)


def test_a_full_message_with_a_body_still_parses():
    """Real .eml files have bodies. The parser reads headers only."""
    data = (MAIL_FIXTURES / "google_aligned.eml").read_bytes()
    data += b"\r\n\r\nHello, your package ships today. evil@nope.example\r\n"
    result = ingest("full.eml", data)
    assert "evil@nope.example" not in plan_values(result)


# --- provenance ------------------------------------------------------------

def test_the_result_says_what_it_read():
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert result.filename == "blocklist.txt"
    assert result.size == len(IP_LIST.encode())


def test_the_plan_does_not_carry_the_file_contents():
    """Same rule as the header block: the plan is persisted as a case."""
    result = ingest("iocs.csv", MIXED_CSV.encode())
    dumped = result.plan.model_dump_json()
    assert "first_seen" not in dumped
    assert "c2" not in dumped or len(dumped) < 100_000


def test_the_case_is_named_after_the_file():
    result = ingest("blocklist.txt", IP_LIST.encode())
    assert "blocklist.txt" in result.plan.case_name


def test_a_dangerous_filename_cannot_escape_the_case_name():
    result = ingest("../../etc/passwd", IP_LIST.encode())
    assert ".." not in result.plan.case_name
    assert "/" not in result.plan.case_name


# --- limits ----------------------------------------------------------------

def test_an_oversized_upload_is_refused_not_truncated_silently():
    result = ingest("huge.txt", b"1.2.3.4\n" * (MAX_BYTES // 4))
    assert result.notes
    assert any("large" in n.lower() or "cap" in n.lower() for n in result.notes)


def test_a_line_bomb_is_capped_and_says_so():
    body = "\n".join(f"10.0.{i // 250}.{i % 250}" for i in range(MAX_LINES * 2))
    result = ingest("many.txt", body.encode())
    assert any(str(MAX_LINES) in n or "truncat" in n.lower() for n in result.notes)


def test_the_seed_count_is_capped():
    from umbra.ingest import MAX_SEEDS

    body = "\n".join(f"host{i}.example.com" for i in range(MAX_SEEDS * 3))
    result = ingest("many.txt", body.encode())
    assert len(result.plan.seeds) <= MAX_SEEDS


def test_a_cap_is_never_silent():
    """A truncated read that says nothing reads as "that was all of it" — the
    same failure as an unchecked source rendering as clean."""
    from umbra.ingest import MAX_SEEDS

    body = "\n".join(f"host{i}.example.com" for i in range(MAX_SEEDS * 3))
    result = ingest("many.txt", body.encode())
    assert result.notes


# --- hostile input ---------------------------------------------------------

def test_an_empty_file_does_not_raise():
    result = ingest("empty.txt", b"")
    assert result.plan.seeds == []
    assert result.notes


def test_random_bytes_do_not_raise():
    result = ingest("noise.bin", bytes(range(256)) * 40)
    assert result.kind is Kind.UNKNOWN
    assert result.notes


def test_invalid_utf8_does_not_raise():
    result = ingest("latin.txt", "café 185.199.108.153\n".encode("latin-1"))
    assert "185.199.108.153" in plan_values(result)


def test_nul_bytes_in_text_do_not_raise():
    ingest("weird.txt", b"1.2.3.4\x00\x00evil.example\n")


def test_malformed_json_falls_back_to_text():
    result = ingest("broken.json", b'{"src_ip": "185.199.108.153", ')
    assert "185.199.108.153" in plan_values(result)


def test_a_zip_bomb_shaped_file_is_refused():
    """A PK header with nothing behind it is not an OOXML document."""
    result = ingest("doc.docx", b"PK\x03\x04" + b"\x00" * 200)
    assert result.notes


def test_no_reader_ever_raises():
    samples = [b"", b"\x00", b"%PDF-", b"PK\x03\x04", b"\xff\xd8\xff",
               b"From:", b"{", b"[", b"\n\n\n", "€".encode()]
    for data in samples:
        for name in ("a.txt", "a.eml", "a.csv", "a.json", "a.pdf", "a.docx",
                     "a.jpg", "", "..", "a" * 300):
            ingest(name, data)


# --- entity types ----------------------------------------------------------

def test_a_domain_list_produces_domain_seeds():
    result = ingest("domains.txt", b"evil-one.example\nevil-two.example\n")
    kinds = {s.type for s in result.plan.seeds if s.include}
    assert EntityType.DOMAIN in kinds
