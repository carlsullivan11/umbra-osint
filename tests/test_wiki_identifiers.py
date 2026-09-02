"""A miss must say which kind of miss it is.

Before this, `umbra lookup` answered three different questions with one
sentence:

    RFC7231        real, obsoleted by 9110    -> silently returned RFC9110
    CVE-2014-3566  POODLE, real, EPSS 0.99999 -> "No wiki hits ... wiki update"
    RFC99999       does not exist             -> the same sentence

Only the third is a miss. The corpus is deliberately scoped — CISA KEV rather
than all 384,910 CVEs, a curated RFC set rather than all 9,834 — and scope is a
good decision. Silence about scope is not, and the "run wiki update" tip blamed
a stale corpus that was not stale.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.wiki.identifiers import Identifier, explain_miss, recognise  # noqa: E402


class TestRecognition:
    @pytest.mark.parametrize("query,kind,canonical", [
        ("CVE-2014-3566", "cve", "CVE-2014-3566"),
        ("cve 2014 3566", "cve", "CVE-2014-3566"),
        ("CWE-79", "cwe", "CWE-79"),
        ("cwe 79", "cwe", "CWE-79"),
        ("CAPEC-66", "capec", "CAPEC-66"),
        ("T1566", "attack", "T1566"),
        ("T1566.001", "attack", "T1566.001"),
        ("RFC7231", "rfc", "RFC7231"),
        ("rfc 826", "rfc", "RFC826"),
        ("RFC0826", "rfc", "RFC826"),
    ])
    def test_identifiers_normalise(self, query, kind, canonical):
        ident = recognise(query)
        assert ident is not None, query
        assert (ident.kind, ident.canonical) == (kind, canonical)

    @pytest.mark.parametrize("query", [
        "log4shell", "dns over https", "", "   ", "spf", "CVE", "RFC",
    ])
    def test_free_text_is_not_an_identifier(self, query):
        """Free text that misses is just a miss — no explanation is owed."""
        assert recognise(query) is None

    def test_every_identifier_carries_an_upstream_url(self):
        for q in ("CVE-2014-3566", "CWE-79", "CAPEC-66", "T1566", "RFC826"):
            ident = recognise(q)
            assert ident.upstream_url.startswith("https://"), q


class TestScopeVersusNonexistence:
    def test_a_real_cve_outside_kev_is_scope_not_absence(self):
        out = explain_miss(recognise("CVE-2014-3566"))
        assert out["verdict"] == "outside_scope"
        assert "scope" in out["headline"]
        # The claim that must never be made.
        assert "does not exist" not in out["headline"]
        assert "KEV" in out["detail"]
        assert "384,910" in out["detail"]

    def test_an_impossible_rfc_number_is_called_a_typo(self):
        out = explain_miss(recognise("RFC99999"))
        assert out["verdict"] == "not_a_document"
        assert "does not appear to exist" in out["headline"]
        assert "typo" in out["detail"]

    def test_a_plausible_rfc_outside_the_set_is_scope(self):
        out = explain_miss(recognise("RFC7231"))
        assert out["verdict"] == "outside_scope"
        assert "9,834" in out["detail"]

    def test_the_two_verdicts_are_never_the_same_sentence(self):
        scope = explain_miss(recognise("RFC7231"))
        gone = explain_miss(recognise("RFC99999"))
        assert scope["headline"] != gone["headline"]


class TestWhatUmbraStillKnows:
    EPSS = {
        "score": 0.99999,
        "band": "high",
        "meaning": "modelled as very likely to be exploited in the next 30 days",
        "model_version": "v2026.06.15",
        "score_date": "2026-08-31T12:00:22Z",
    }

    def test_a_known_epss_score_is_surfaced_on_a_wiki_miss(self):
        """The point of the whole module. POODLE is not in KEV, but the lake
        next door scores it 0.99999 — reporting "no hits" while holding that is
        the lookup-shaped version of calling an unchecked source clean."""
        out = explain_miss(recognise("CVE-2014-3566"), epss=self.EPSS)
        assert out["known"], "a known score must not be withheld"
        assert "0.99999" in out["known"][0]
        assert "v2026.06.15" in out["known"][0], "a score without its model is not evidence"

    def test_no_epss_says_unscored_is_not_low(self):
        out = explain_miss(recognise("CVE-2014-3566"), epss=None)
        assert any("Unscored is not low" in k for k in out["known"])

    def test_a_nonexistent_document_claims_no_knowledge(self):
        out = explain_miss(recognise("RFC99999"))
        assert out["known"] == []


class TestServiceIntegration:
    def test_explain_returns_none_for_free_text(self, tmp_path):
        from umbra.wiki.service import WikiService

        svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "i.sqlite")
        assert svc.explain("some free text query") is None

    def test_explain_survives_a_missing_epss_lake(self, tmp_path, monkeypatch):
        """A lookup must not break because a lake is absent."""
        from umbra.core.config import Settings
        from umbra.wiki.service import WikiService

        svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "i.sqlite")
        out = svc.explain("CVE-2014-3566", settings=Settings(data_dir=tmp_path))
        assert out is not None
        assert out["verdict"] == "outside_scope"
