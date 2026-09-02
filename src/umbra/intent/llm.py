"""OpenAI-compatible LLM planner for Intent (Phase II).

Works with LocalAI, OpenAI, vLLM, llama.cpp server, etc.
Returns a partial plan dict; merge layer combines with deterministic hits.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from umbra.core.config import Settings
from umbra.intent.schema import IntentFlags, IntentSeed
from umbra.core.models import EntityType

log = logging.getLogger("umbra.intent.llm")

SYSTEM_PROMPT = """You are Umbra Intent Planner — a structured OSINT intake assistant.
You convert messy operator notes into JSON only (no markdown fences, no prose).

Rules:
1. Extract ONLY identifiers supported by the user text. Do not invent emails, phones, SSNs, or addresses.
2. Prefer platform-prefixed usernames: github:handle, twitter:handle, linkedin:slug, instagram:handle.
3. Set confidence 0.0-1.0. Explicit mentions >=0.85; implied 0.55-0.84; guesses <0.55.
4. Set include=false for guesses under 0.55.
5. Flags: set booleans if the user wants lookalikes/typosquats, breaches/HIBP, corp records, username probing, web search, wayback.
6. If the request is clearly unauthorized harassment/doxxing of a private person with no legitimate investigation framing, set refuse=true and refuse_reason.
7. clarifying_questions: ask only if critical identifiers are missing.
8. case_name: short label. summary: one line.
9. Do NOT list collectors — the server maps collectors from seeds/flags.
10. Respond with a single JSON object matching the schema.

JSON schema:
{
  "case_name": "string",
  "summary": "string",
  "seeds": [
    {"type": "domain|email|username|person|org|ip|url|phone",
     "value": "string",
     "confidence": 0.0,
     "include": true,
     "notes": "string or null",
     "source_span": "substring from text or null"}
  ],
  "flags": {
    "want_lookalikes": false,
    "want_breaches": false,
    "want_corp_records": false,
    "aggressive_username_probe": false,
    "want_web_search": false,
    "want_wayback": false
  },
  "warnings": ["string"],
  "clarifying_questions": ["string"],
  "refuse": false,
  "refuse_reason": null
}
"""


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    raw = _strip_fences(text)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # find first {...}
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        data = json.loads(raw[start : end + 1])
        if isinstance(data, dict):
            return data
    raise ValueError("LLM response was not valid JSON object")


def build_user_prompt(
    text: str,
    *,
    basis: str,
    note: str,
    deterministic_seeds: list[IntentSeed],
    deterministic_flags: IntentFlags,
) -> str:
    det = {
        "seeds": [
            {
                "type": s.type.value,
                "value": s.value,
                "confidence": s.confidence,
                "include": s.include,
                "notes": s.notes,
            }
            for s in deterministic_seeds
        ],
        "flags": deterministic_flags.model_dump(),
    }
    return (
        f"Authorization basis: {basis}\n"
        f"Authorization note: {note or '(none)'}\n\n"
        f"Deterministic extractor already found (prefer keeping these; add missing only):\n"
        f"{json.dumps(det, indent=2)}\n\n"
        f"Operator intent text:\n---\n{text}\n---\n\n"
        "Return the full JSON plan object."
    )


def call_chat_completions(
    settings: Settings,
    *,
    system: str,
    user: str,
) -> str:
    if not settings.llm_base_url:
        raise RuntimeError("UMBRA_LLM_BASE_URL not set")
    base = settings.llm_base_url.rstrip("/")
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.llm_api_key:
        headers["Authorization"] = f"Bearer {settings.llm_api_key}"
    body = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": settings.llm_temperature,
        "max_tokens": settings.llm_max_tokens,
    }
    # Some servers support json mode
    body["response_format"] = {"type": "json_object"}

    with httpx.Client(timeout=settings.llm_timeout_s) as client:
        try:
            resp = client.post(url, headers=headers, json=body)
        except httpx.HTTPError:
            # retry without response_format for LocalAI/older servers
            body.pop("response_format", None)
            resp = client.post(url, headers=headers, json=body)
        if resp.status_code >= 400 and "response_format" in body:
            body.pop("response_format", None)
            resp = client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        data = resp.json()

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"Unexpected LLM response shape: {data!r}") from exc


_ALLOWED_TYPES = {
    "domain",
    "email",
    "username",
    "person",
    "org",
    "ip",
    "url",
    "phone",
    "repo",
}


def parse_llm_plan_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize/validate LLM dict into merge-friendly structure."""
    seeds_out: list[IntentSeed] = []
    for raw in data.get("seeds") or []:
        if not isinstance(raw, dict):
            continue
        t = str(raw.get("type") or "").lower().strip()
        if t not in _ALLOWED_TYPES:
            continue
        val = str(raw.get("value") or "").strip()
        if not val:
            continue
        try:
            et = EntityType(t)
        except ValueError:
            continue
        conf = float(raw.get("confidence") if raw.get("confidence") is not None else 0.7)
        conf = max(0.0, min(1.0, conf))
        include = raw.get("include")
        if include is None:
            include = conf >= 0.55
        seeds_out.append(
            IntentSeed(
                type=et,
                value=val,
                confidence=conf,
                include=bool(include),
                notes=raw.get("notes"),
                source_span=raw.get("source_span"),
                props={"from_llm": True},
            )
        )

    flags_raw = data.get("flags") or {}
    if not isinstance(flags_raw, dict):
        flags_raw = {}
    flags = IntentFlags(
        want_lookalikes=bool(flags_raw.get("want_lookalikes", False)),
        want_breaches=bool(flags_raw.get("want_breaches", False)),
        want_corp_records=bool(flags_raw.get("want_corp_records", False)),
        aggressive_username_probe=bool(flags_raw.get("aggressive_username_probe", False)),
        want_web_search=bool(flags_raw.get("want_web_search", False)),
        want_wayback=bool(flags_raw.get("want_wayback", False)),
    )

    warnings = [str(w) for w in (data.get("warnings") or []) if w]
    questions = [str(q) for q in (data.get("clarifying_questions") or []) if q]
    refuse = bool(data.get("refuse", False))
    refuse_reason = data.get("refuse_reason")
    if refuse_reason is not None:
        refuse_reason = str(refuse_reason)

    return {
        "case_name": (str(data["case_name"]).strip() if data.get("case_name") else None),
        "summary": (str(data["summary"]).strip() if data.get("summary") else None),
        "seeds": seeds_out,
        "flags": flags,
        "warnings": warnings,
        "clarifying_questions": questions,
        "refuse": refuse,
        "refuse_reason": refuse_reason,
    }


def llm_enrich(
    settings: Settings,
    *,
    text: str,
    basis: str,
    note: str,
    deterministic_seeds: list[IntentSeed],
    deterministic_flags: IntentFlags,
) -> dict[str, Any]:
    """Call LLM and return normalized partial plan dict."""
    user = build_user_prompt(
        text,
        basis=basis,
        note=note,
        deterministic_seeds=deterministic_seeds,
        deterministic_flags=deterministic_flags,
    )
    content = call_chat_completions(settings, system=SYSTEM_PROMPT, user=user)
    data = _extract_json_object(content)
    return parse_llm_plan_dict(data)
