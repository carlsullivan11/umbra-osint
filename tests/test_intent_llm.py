from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.intent.llm import parse_llm_plan_dict, llm_enrich
from umbra.intent.merge import merge_flags, merge_seeds
from umbra.intent.plan import analyze_intent
from umbra.intent.schema import AnalyzeRequest, IntentFlags, IntentSeed


def test_merge_seeds_union_max_conf():
    det = [
        IntentSeed(type=EntityType.DOMAIN, value="Example.COM", confidence=0.9, include=True),
        IntentSeed(type=EntityType.EMAIL, value="a@example.com", confidence=0.95, include=True),
    ]
    llm = [
        IntentSeed(type=EntityType.DOMAIN, value="example.com", confidence=0.7, include=True),
        IntentSeed(
            type=EntityType.USERNAME,
            value="github:octocat",
            confidence=0.88,
            include=True,
            props={"from_llm": True},
        ),
    ]
    merged = merge_seeds(det, llm)
    by = {s.value: s for s in merged}
    assert "example.com" in by
    assert by["example.com"].confidence == 0.9
    assert "github:octocat" in by
    assert "deterministic" in by["example.com"].props.get("sources", [])


def test_merge_flags_or():
    a = IntentFlags(want_breaches=True)
    b = IntentFlags(want_lookalikes=True)
    m = merge_flags(a, b)
    assert m.want_breaches and m.want_lookalikes


def test_parse_llm_plan_dict():
    data = {
        "case_name": "Acme check",
        "summary": "Domain + gh",
        "seeds": [
            {"type": "domain", "value": "acme.example", "confidence": 0.9, "include": True},
            {"type": "username", "value": "github:acme", "confidence": 0.8, "include": True},
            {"type": "bogus", "value": "x", "confidence": 0.9},
        ],
        "flags": {"want_breaches": True, "want_lookalikes": False},
        "warnings": ["note"],
        "clarifying_questions": [],
        "refuse": False,
        "refuse_reason": None,
    }
    part = parse_llm_plan_dict(data)
    assert part["case_name"] == "Acme check"
    assert len(part["seeds"]) == 2
    assert part["flags"].want_breaches is True


@respx.mock
def test_llm_enrich_http_mock():
    base = "http://llm.test/v1"
    settings = Settings(
        data_dir=Path("/tmp/umbra-test-llm"),
        llm_base_url=base,
        llm_model="test-model",
        llm_api_key="sk-test",
        llm_enabled=True,
    )
    payload = {
        "case_name": "Messy org",
        "summary": "Inferred org and handle",
        "seeds": [
            {
                "type": "org",
                "value": "Acme Robotics",
                "confidence": 0.8,
                "include": True,
                "notes": "from prose",
            },
            {
                "type": "username",
                "value": "github:acmerobot",
                "confidence": 0.75,
                "include": True,
            },
        ],
        "flags": {"want_corp_records": True},
        "warnings": [],
        "clarifying_questions": [],
        "refuse": False,
        "refuse_reason": None,
    }
    respx.post(f"{base}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(payload)}}]},
        )
    )
    det_seeds = [
        IntentSeed(type=EntityType.DOMAIN, value="acme.example", confidence=0.9, include=True)
    ]
    out = llm_enrich(
        settings,
        text="Look into Acme Robotics, I think their github is acmerobot, domain acme.example",
        basis="client_engagement",
        note="test",
        deterministic_seeds=det_seeds,
        deterministic_flags=IntentFlags(),
    )
    assert out["case_name"] == "Messy org"
    assert any(s.type == EntityType.ORG for s in out["seeds"])
    assert out["flags"].want_corp_records is True


@respx.mock
def test_analyze_intent_with_llm_merge(tmp_path: Path):
    base = "http://llm.test/v1"
    settings = Settings(
        data_dir=tmp_path,
        llm_base_url=base,
        llm_model="test-model",
        llm_enabled=True,
    )
    payload = {
        "case_name": "Brand watch",
        "summary": "Brand + social",
        "seeds": [
            {
                "type": "username",
                "value": "instagram:examplebrand",
                "confidence": 0.7,
                "include": True,
                "notes": "mentioned casually",
            }
        ],
        "flags": {"want_lookalikes": True, "want_breaches": True},
        "warnings": ["IG handle uncertain"],
        "clarifying_questions": [],
        "refuse": False,
        "refuse_reason": None,
    }
    respx.post(f"{base}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(payload)}}]},
        )
    )
    text = (
        "Our brand example-brand.com and maybe IG examplebrand; "
        "email hello@example-brand.com — check lookalikes and breaches"
    )
    plan = analyze_intent(
        AnalyzeRequest(text=text, authorization_basis="own_asset", use_llm=True),
        settings=settings,
    )
    assert "llm" in plan.extractor
    vals = {s.value for s in plan.seeds if s.include}
    assert "example-brand.com" in vals
    assert "hello@example-brand.com" in vals
    assert "instagram:examplebrand" in vals
    assert plan.flags.want_lookalikes and plan.flags.want_breaches
    assert "lookalike_domains" in plan.collectors
    assert any("IG handle" in w or "uncertain" in w.lower() for w in plan.warnings)


def test_analyze_intent_llm_requested_but_unconfigured(tmp_path: Path):
    settings = Settings(data_dir=tmp_path, llm_base_url=None, llm_enabled=False)
    plan = analyze_intent(
        AnalyzeRequest(text="example.com", authorization_basis="training_lab", use_llm=True),
        settings=settings,
    )
    assert any("not configured" in w for w in plan.warnings)
    assert plan.extractor.startswith("deterministic")
