"""Jev client: request shape, parsing, cache, budget, failure modes — docs/JEV.md §2, §7."""
from __future__ import annotations

import pytest

from jev_fake import FakeJev
from umbra.core.config import Settings
from umbra.jev.client import JevClient, JevUnavailable, parse_answer, parse_response, provider_headers
from umbra.jev.questions import INFRA_ROLE, PHISH_LINK, Choice, Noul, Score, to_wire


def test_request_carries_bearer_key_model_state_and_questions(tmp_path):
    fake = FakeJev()
    res = fake.client(tmp_path, model="jev-1.13").ask("Subject: ip 192.0.2.1", INFRA_ROLE.questions)
    call = fake.calls[0]
    assert call["headers"]["authorization"] == "Bearer ts-test-key"
    assert call["body"]["model"] == "jev-1.13"
    assert call["body"]["state"] == "Subject: ip 192.0.2.1"
    role = call["body"]["questions"]["role"]
    assert role["type"] == "choice" and "instructions" in role and "clean" in role["criteria"]
    assert res.answers["role"].type == "choice"
    assert res.model == "typesafe/jev-1.13"
    assert res.input_tokens == 423


def test_second_identical_ask_is_served_from_cache(tmp_path):
    fake = FakeJev()
    client = fake.client(tmp_path)
    first = client.ask("s", INFRA_ROLE.questions)
    second = client.ask("s", INFRA_ROLE.questions)
    assert len(fake.calls) == 1
    assert not first.cached and second.cached
    assert second.answers == first.answers


def test_missing_key_is_unavailable_and_makes_no_call(tmp_path):
    fake = FakeJev()
    with pytest.raises(JevUnavailable, match="API_KEY"):
        fake.client(tmp_path, api_key=None).ask("s", INFRA_ROLE.questions)
    assert fake.calls == []


@pytest.mark.parametrize("status", [401, 429, 500, 503])
def test_http_errors_are_unavailable(tmp_path, status):
    with pytest.raises(JevUnavailable, match=str(status)):
        FakeJev(status=status).client(tmp_path).ask("s", INFRA_ROLE.questions)


def test_budget_exhaustion_stops_calls(tmp_path):
    fake = FakeJev(input_tokens=None)  # exercise the estimate path
    fake.client(tmp_path).ask("first", INFRA_ROLE.questions)
    used = fake.client(tmp_path).tokens_used_today()
    assert used > 0
    tight = fake.client(tmp_path, daily_token_budget=used + 10)
    with pytest.raises(JevUnavailable, match="budget"):
        tight.ask("second " + "x" * 200, INFRA_ROLE.questions)
    assert len(fake.calls) == 1


def test_budget_zero_means_unlimited(tmp_path):
    client = FakeJev().client(tmp_path, daily_token_budget=0)
    for i in range(3):
        client.ask(f"state {i}", INFRA_ROLE.questions)


def test_transport_failure_is_unavailable(tmp_path):
    import httpx

    def boom(request):
        raise httpx.ConnectTimeout("slow", request=request)

    client = JevClient("k", cache_dir=tmp_path,
                       http_factory=lambda: httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(JevUnavailable, match="transport"):
        client.ask("s", INFRA_ROLE.questions)


def test_default_client_goes_through_the_egress_guard():
    from umbra.core.http_guard import GuardedClient
    assert isinstance(JevClient("k")._client(), GuardedClient)


def test_parse_is_defensive():
    assert parse_answer({"type": "noul", "probability": 0.4}).probability == 0.4
    assert parse_answer({"type": "noul", "noul": 0.3}).probability == 0.3
    assert parse_answer({"type": "noul", "yes_probability": 0.2}).probability == 0.2
    assert parse_answer({"type": "choice", "winner": "b", "probabilities": {"b": 1}}).value == "b"
    a = parse_answer({"type": "choice", "probabilities": {"x": 0.2, "y": 0.8}})
    assert a.value == "y" and a.confidence is None
    # out-of-range probabilities are dropped, not trusted
    a = parse_answer({"type": "choice", "choice": "x", "probabilities": {"x": 7}, "confidence": 2})
    assert a.probabilities == {} and a.confidence is None
    with pytest.raises(JevUnavailable):
        parse_answer({"type": "noul"})
    with pytest.raises(JevUnavailable):
        parse_answer({"type": "essay", "text": "hi"})
    with pytest.raises(JevUnavailable, match="missing"):
        parse_response({"answers": {}}, {"role": None}, "h")
    with pytest.raises(JevUnavailable):
        parse_response(["nope"], {"role": None}, "h")
    with pytest.raises(JevUnavailable, match="error"):
        parse_response({"error": {"code": 402}}, {"role": None}, "h")


def test_question_validation_and_wire_shape():
    with pytest.raises(ValueError):
        Choice("q", {"only": "one"})
    with pytest.raises(ValueError):
        Score("q", ("a",))
    assert to_wire(Score("q", ("low", "high"))) == {
        "type": "score", "instructions": "q", "criteria": ["low", "high"]}
    assert to_wire(Choice("q", {"a": "x", "b": "y"})) == {
        "type": "choice", "instructions": "q", "criteria": {"a": "x", "b": "y"}}
    assert to_wire(Noul("q")) == {"type": "noul", "instructions": "q"}


def test_settings_default_off_and_route_through_openrouter(monkeypatch, tmp_path):
    for var in ("UMBRA_JEV_ENABLED", "UMBRA_OPENROUTER_API_KEY", "UMBRA_TYPESAFE_API_KEY",
                "UMBRA_JEV_PROVIDER", "UMBRA_JEV_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    s = Settings(data_dir=tmp_path, _env_file=None)
    assert not s.jev_enabled and not s.jev_configured
    assert s.jev_provider == "openrouter"

    s = Settings(data_dir=tmp_path, _env_file=None, jev_enabled=True, openrouter_api_key="or-k")
    assert s.jev_configured
    c = JevClient.from_settings(s)
    assert c.url == "https://openrouter.ai/api/v1/systemone"
    assert c.api_key == "or-k"
    assert c.extra_headers["X-Title"] == "Umbra OSINT"
    assert c.cache_dir == tmp_path / "cache" / "jev"

    # a TypeSafe key does not count while the provider is OpenRouter
    s = Settings(data_dir=tmp_path, _env_file=None, jev_enabled=True, typesafe_api_key="ts-k")
    assert not s.jev_configured

    s = Settings(data_dir=tmp_path, _env_file=None, jev_enabled=True, jev_provider="typesafe",
                 typesafe_api_key="ts-k")
    c = JevClient.from_settings(s)
    assert s.jev_configured and c.api_key == "ts-k"
    assert c.url == "https://api.typesafe.ai/v1/systemone" and c.extra_headers == {}

    s = Settings(data_dir=tmp_path, _env_file=None, jev_base_url="https://gw.example/api/")
    assert JevClient.from_settings(s).url == "https://gw.example/api/v1/systemone"


def test_openrouter_headers_are_sent(tmp_path):
    fake = FakeJev()
    fake.client(tmp_path, extra_headers=provider_headers("openrouter")).ask("s", INFRA_ROLE.questions)
    assert fake.calls[0]["headers"]["x-title"] == "Umbra OSINT"
    assert fake.calls[0]["headers"]["http-referer"] == "https://umbra-osint.com"


def test_decisions_shape_parses_the_same(tmp_path):
    a = FakeJev().client(tmp_path / "a").ask("s", PHISH_LINK.questions)
    b = FakeJev(decisions_shape=True).client(tmp_path / "b").ask("s", PHISH_LINK.questions)
    assert a.answers == b.answers


def test_budget_bills_reported_usage(tmp_path):
    client = FakeJev(input_tokens=423).client(tmp_path)
    client.ask("s", INFRA_ROLE.questions)
    assert client.tokens_used_today() == 423


def test_score_positions_map_back_to_level_words():
    q = Score("How risky?", ("low", "medium", "high"))
    a = parse_answer({"type": "score", "score": 2, "confidence": 0.9,
                      "probabilities": {"0": 0.0, "1": 0.1, "2": 0.9}}, q)
    assert a.value == "high" and a.probabilities == {"low": 0.0, "medium": 0.1, "high": 0.9}
    a = parse_answer({"type": "score", "score": 1.4, "probabilities": {}}, q)
    assert a.value == "medium"
    a = parse_answer({"type": "score", "score": 0, "label": "low"}, None)
    assert a.value == "low"
    a = parse_answer({"type": "score", "score": 1, "legend": {"1": "medium"}}, None)
    assert a.value == "medium"
