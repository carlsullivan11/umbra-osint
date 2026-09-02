"""The note wall, tested against the real one.

Every string below was produced by an actual run of
`umbra intent "umbra-osint.com, analyst@example.com, GH example-user"`.
33 lines, 15 distinct conditions.
"""
from __future__ import annotations

import httpx
import pytest

from umbra.core.notes import (
    NoteKind,
    classify,
    describe_http_failure,
    summarize,
    summarize_by_kind,
)

# Verbatim from the run, in the order it emitted them.
REAL_RUN = [
    "ct_lake: no certs for umbra-osint.com in the owned corpus (2,100 certs ingested — corpus is tail-forward; run `umbra ct ingest` to grow it)",
    "crt.sh unavailable for umbra-osint.com (HTTP 502) — this is NOT 'no certificates'; the source could not be reached. The owned corpus (`ct_lake`) is unaffected.",
    "security.txt not found",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
    "github_commits on username:github:carlsullivan11: timeout after 45s",
    "GeoIP lake not loaded — run `umbra geoip sync` (free DB-IP City Lite). Location is unchecked, not empty.",
    "spamhaus_zen: resolver error: All nameservers failed to answer the query 109.72.21.104.zen.spamhaus.org.",
    "feodo_tracker error: Server error '503 certificate has expired' for url 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'",
    "abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)",
    "reputation: clean (score 0, 0/2 sources listed)",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
    "GeoIP lake not loaded — run `umbra geoip sync` (free DB-IP City Lite). Location is unchecked, not empty.",
    "feodo_tracker error: Server error '503 certificate has expired' for url 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'",
    "abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)",
    "reputation: clean (score 0, 0/2 sources listed)",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
    "GeoIP lake not loaded — run `umbra geoip sync` (free DB-IP City Lite). Location is unchecked, not empty.",
    "spamhaus_zen: skipped (not IPv4)",
    "feodo_tracker error: Server error '503 certificate has expired' for url 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'",
    "abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)",
    "reputation: clean (score 0, 0/1 sources listed)",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
    "RDAP IP error: The read operation timed out",
    "GeoIP lake not loaded — run `umbra geoip sync` (free DB-IP City Lite). Location is unchecked, not empty.",
    "spamhaus_zen: skipped (not IPv4)",
    "feodo_tracker error: Server error '503 certificate has expired' for url 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'",
    "abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)",
    "reputation: clean (score 0, 0/1 sources listed)",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
    "ct_lake: no certs for gmail.com in the owned corpus (2,100 certs ingested — corpus is tail-forward; run `umbra ct ingest` to grow it)",
    "crt.sh unavailable for gmail.com (HTTP 502) — this is NOT 'no certificates'; the source could not be reached. The owned corpus (`ct_lake`) is unaffected.",
    "security.txt not found",
    "malware_infra: urlhaus, threatfox, feodo not checked — never synced into this lake (run `umbra abuse sync`)",
]


class TestAggregation:
    def test_collapses_the_wall(self):
        groups = summarize(REAL_RUN)
        assert len(REAL_RUN) == 33
        # 15 distinct conditions was the hand count; the summary must not be
        # longer than the thing it summarises by more than a rounding error.
        assert len(groups) <= 16, [g.message for g in groups]
        assert len(groups) < len(REAL_RUN) / 2

    def test_counts_the_repeats(self):
        groups = {g.message.split(":")[0]: g for g in summarize(REAL_RUN)}
        malware = next(g for g in summarize(REAL_RUN) if "malware_infra" in g.message)
        assert malware.count == 6
        geoip = next(g for g in summarize(REAL_RUN) if "GeoIP" in g.message)
        assert geoip.count == 4

    def test_folds_the_same_condition_about_different_subjects(self):
        # ct_lake said the same thing about umbra-osint.com and gmail.com.
        groups = summarize(REAL_RUN)
        # startswith, not "in": the crt.sh note also mentions ct_lake, saying
        # the owned corpus is unaffected.
        ct = [g for g in groups if g.message.startswith("ct_lake")]
        assert len(ct) == 1
        assert ct[0].count == 2
        assert "umbra-osint.com" in ct[0].subjects
        assert "gmail.com" in ct[0].subjects

    def test_names_the_affected_subjects(self):
        ct = next(g for g in summarize(REAL_RUN) if g.message.startswith("ct_lake"))
        assert "gmail.com" in ct.detail

    def test_is_stable(self):
        # Case exports get diffed; unstable ordering makes that noise.
        assert [g.message for g in summarize(REAL_RUN)] == [
            g.message for g in summarize(REAL_RUN)
        ]

    def test_empty_and_blank_are_dropped(self):
        assert summarize([]) == []
        assert summarize(["", "   ", "\n"]) == []

    def test_a_stack_trace_is_one_condition(self):
        multi = ["boom: it broke\n  File x, line 1\n  File y, line 2"] * 3
        groups = summarize(multi)
        assert len(groups) == 1
        assert "\n" not in groups[0].message


class TestClassification:
    @pytest.mark.parametrize(
        "note,kind",
        [
            ("reputation: clean (score 0, 0/2 sources listed)", NoteKind.RESULT),
            ("security.txt not found", NoteKind.RESULT),
            ("abuseipdb: skipped (no UMBRA_ABUSEIPDB_API_KEY)", NoteKind.NOT_CONFIGURED),
            (
                "GeoIP lake not loaded — run `umbra geoip sync` (free DB-IP City Lite).",
                NoteKind.NOT_CONFIGURED,
            ),
            (
                "malware_infra: urlhaus not checked — never synced into this lake",
                NoteKind.NOT_CONFIGURED,
            ),
            ("crt.sh unavailable for x.com (HTTP 502)", NoteKind.SOURCE_FAILED),
            ("RDAP IP error: The read operation timed out", NoteKind.SOURCE_FAILED),
            ("github_commits on username:x: timeout after 45s", NoteKind.SOURCE_FAILED),
            ("job wall-clock budget reached (120s); stopping early", NoteKind.LIMIT),
            ("max_entities reached", NoteKind.LIMIT),
        ],
    )
    def test_each_line_lands_in_the_right_bucket(self, note, kind):
        assert classify(note) == kind

    def test_a_result_is_never_filed_as_a_warning(self):
        # The whole point: "clean" is an answer, not a problem with the answer.
        by_kind = summarize_by_kind(REAL_RUN)
        results = [g.message for g in by_kind.get(NoteKind.RESULT, [])]
        assert any("reputation: clean" in m for m in results)
        assert not any("clean" in g.message for g in by_kind.get(NoteKind.SOURCE_FAILED, []))

    def test_unreachable_and_unconfigured_do_not_share_a_bucket(self):
        by_kind = summarize_by_kind(REAL_RUN)
        failed = " ".join(g.message for g in by_kind[NoteKind.SOURCE_FAILED])
        chores = " ".join(g.message for g in by_kind[NoteKind.NOT_CONFIGURED])
        assert "crt.sh" in failed and "crt.sh" not in chores
        assert "ABUSEIPDB" in chores and "ABUSEIPDB" not in failed

    def test_carries_the_remedy(self):
        geoip = next(g for g in summarize(REAL_RUN) if "GeoIP" in g.message)
        assert geoip.remedy == "umbra geoip sync"
        clean = next(g for g in summarize(REAL_RUN) if "reputation: clean" in g.message)
        assert clean.remedy is None


class TestHttpFailureWording:
    """U3 — a remote server's words are data, not our diagnosis."""

    def test_does_not_repeat_a_remote_reason_phrase(self):
        # abuse.ch returns 503 with the Varnish reason phrase "certificate has
        # expired". Their certificate is valid (GlobalSign, good to Jan 2027).
        # The old message read `feodo_tracker error: Server error '503
        # certificate has expired'`, which sends an operator to debug TLS.
        request = httpx.Request("GET", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        response = httpx.Response(503, request=request)
        exc = httpx.HTTPStatusError("Server error '503 certificate has expired'", request=request, response=response)

        msg = describe_http_failure("feodo_tracker", exc)

        assert "certificate" not in msg.lower()
        assert "503" in msg
        assert "feodotracker.abuse.ch" in msg
        assert "unreachable" in msg.lower()

    def test_says_unknown_rather_than_clean(self):
        request = httpx.Request("GET", "https://example.org/x")
        exc = httpx.HTTPStatusError(
            "boom", request=request, response=httpx.Response(502, request=request)
        )
        assert "unknown rather than clean" in describe_http_failure("src", exc)

    def test_handles_a_transport_error_with_no_response(self):
        exc = httpx.ConnectTimeout("timed out", request=httpx.Request("GET", "https://example.org/"))
        msg = describe_http_failure("src", exc)
        assert "ConnectTimeout" in msg
        assert "example.org" in msg

    def test_classified_as_a_source_failure(self):
        request = httpx.Request("GET", "https://feodotracker.abuse.ch/x")
        exc = httpx.HTTPStatusError(
            "x", request=request, response=httpx.Response(503, request=request)
        )
        assert classify(describe_http_failure("feodo_tracker", exc)) == NoteKind.SOURCE_FAILED


class TestSubjectNoise:
    """The detail line must name the operator's entities, not the source's URL."""

    def test_silent_when_every_occurrence_names_the_same_thing(self):
        # feodo_tracker failed four times, always about the same URL. Listing
        # "feodotracker.abuse.ch, ipblocklist.json" underneath told the reader
        # nothing except that a filename looks like a hostname to a regex.
        feodo = next(g for g in summarize(REAL_RUN) if "feodo_tracker" in g.message)
        assert feodo.count == 4
        assert feodo.detail == ""

    def test_speaks_when_the_occurrences_genuinely_differ(self):
        # ct_lake failed for two different domains. That is worth naming.
        ct = next(g for g in summarize(REAL_RUN) if g.message.startswith("ct_lake"))
        assert "umbra-osint.com" in ct.detail
        assert "gmail.com" in ct.detail

    def test_drops_the_subject_that_every_occurrence_shares(self):
        # "crt.sh unavailable for umbra-osint.com" / "... for gmail.com":
        # crt.sh is the source that failed, present in both, so it identifies
        # nothing. The two domains are the story.
        crt = next(g for g in summarize(REAL_RUN) if g.message.startswith("crt.sh"))
        assert "crt.sh" not in crt.detail
        assert "umbra-osint.com" in crt.detail and "gmail.com" in crt.detail
