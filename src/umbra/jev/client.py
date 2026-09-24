"""Thin client for TypeSafe's Jev (`POST {base}/v1/systemone`), docs/JEV.md §2.

- Provider: OpenRouter by default (`UMBRA_JEV_PROVIDER=openrouter`, key in
  `UMBRA_OPENROUTER_API_KEY`); TypeSafe direct is one setting away.

- Egress goes through `umbra.core.http_guard.GuardedClient`, like every
  collector. The host is public; the point is one egress path.
- Every failure — no key, timeout, 4xx/5xx, a body we cannot parse, budget
  spent — raises `JevUnavailable`. Callers catch it and keep the deterministic
  verdict. Nothing downstream depends on Jev answering.
- Answers are cached on disk by (model, questions, state), so a repeated lookup
  is free and an audited answer can be reproduced.
- The daily budget is counted in *input tokens* (the only thing Jev bills),
  taken from the response's `usage` when present, else estimated at 4
  characters per token. It bounds abuse and runaway loops, not
  cost — see §8.

Two response shapes are seen in the wild (`answers` with `choice`/`noul`,
`decisions` with `winner`/`yes_probability`); `parse_response` reads both.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import httpx

from umbra.jev.questions import Question, Score, to_wire

#: Where `{base}/v1/systemone` lives per provider. OpenRouter serves the same
#: System One API under /api, billed to an OpenRouter key; bare model names
#: (`jev-1.13`) map to `typesafe/jev-1.13` there.
PROVIDER_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api",
    "typesafe": "https://api.typesafe.ai",
}
DEFAULT_BASE_URL = PROVIDER_BASE_URLS["openrouter"]
ENDPOINT = "/v1/systemone"


def provider_headers(provider: str) -> dict[str, str]:
    """OpenRouter's optional app-attribution headers; nothing for TypeSafe."""
    if provider == "openrouter":
        return {"HTTP-Referer": "https://umbra-osint.com", "X-Title": "Umbra OSINT"}
    return {}
CACHE_TTL_S = 6 * 3600.0


class JevUnavailable(Exception):
    """Jev did not produce a usable answer. Fall back to the deterministic verdict."""


@dataclass
class Answer:
    type: str
    #: Choice: the picked option · Score: the picked level · Noul: None
    value: str | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    #: Choice/Score only. Noul has none; use `probability`.
    confidence: float | None = None
    #: Noul only: P(yes)
    probability: float | None = None


@dataclass
class JevResult:
    model: str
    answers: dict[str, Answer]
    state_hash: str
    cached: bool = False
    #: as reported by the provider's `usage`; None when it did not say
    input_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model, "state_hash": self.state_hash,
                "answers": {k: asdict(v) for k, v in self.answers.items()}}

    @classmethod
    def from_dict(cls, data: dict[str, Any], cached: bool = False) -> "JevResult":
        return cls(model=data["model"], state_hash=data["state_hash"], cached=cached,
                   answers={k: Answer(**v) for k, v in data["answers"].items()})


def _float(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 1.0 else None


def _first_float(raw: dict[str, Any], *keys: str) -> float | None:
    for k in keys:
        if (f := _float(raw.get(k))) is not None:
            return f
    return None


def parse_answer(raw: dict[str, Any], question: Question | None = None) -> Answer:
    """One answer, in either shape Jev endpoints are seen to return.

    Noul: `noul` | `yes_probability` | `probability`. Choice: `choice` |
    `winner`. Score: `score` (an index into the rubric, possibly fractional)
    with `label`/`legend`; mapped back to the level's own words when the
    question is known, so callers never handle indices.
    """
    kind = str(raw.get("type") or "").lower()
    probs = {str(k): p for k, v in (raw.get("probabilities") or {}).items()
             if (p := _float(v)) is not None}
    if kind == "noul":
        p = _first_float(raw, "noul", "yes_probability", "probability", "value")
        if p is None:
            raise JevUnavailable("noul answer without a probability")
        return Answer(type="noul", probability=p)
    if kind == "choice":
        value = next((raw[k] for k in ("choice", "winner", "value") if raw.get(k) is not None), None)
        if value is None and probs:
            value = max(probs, key=probs.__getitem__)
        if value is None:
            raise JevUnavailable("choice answer without a pick")
        return Answer(type="choice", value=str(value), probabilities=probs,
                      confidence=_float(raw.get("confidence")))
    if kind == "score":
        levels = list(question.levels) if isinstance(question, Score) else []
        idx = raw.get("score", raw.get("value"))
        if levels:
            # rubric positions -> level words; drop anything out of range
            named: dict[str, float] = {}
            for k, p in probs.items():
                try:
                    i = int(k)
                except ValueError:
                    named[k] = p
                    continue
                if 0 <= i < len(levels):
                    named[levels[i]] = p
            probs = named
        label = raw.get("label") or (raw.get("legend") or {}).get(str(idx))
        if label is None and levels and isinstance(idx, (int, float)):
            i = int(round(idx))
            if 0 <= i < len(levels):
                label = levels[i]
        if label is None and idx is not None:
            label = str(idx)
        if label is None and probs:
            label = max(probs, key=probs.__getitem__)
        if label is None:
            raise JevUnavailable("score answer without a position")
        return Answer(type="score", value=str(label), probabilities=probs,
                      confidence=_float(raw.get("confidence")))
    raise JevUnavailable(f"unknown answer type {kind!r}")


def parse_response(data: Any, questions: Mapping[str, Question | None],
                   state_hash: str) -> JevResult:
    """Parse a full response. The answers map is `answers` or `decisions`."""
    if isinstance(data, dict) and data.get("error"):
        raise JevUnavailable("provider returned an error")
    amap = None
    if isinstance(data, dict):
        amap = data.get("answers") if isinstance(data.get("answers"), dict) else data.get("decisions")
    if not isinstance(amap, dict):
        raise JevUnavailable("response has no answers map")
    answers = {k: parse_answer(v, questions.get(k)) for k, v in amap.items()
               if k in questions and isinstance(v, dict)}
    missing = set(questions) - answers.keys()
    if missing:
        raise JevUnavailable(f"response missing answers: {sorted(missing)}")
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    tokens = usage.get("input_tokens")
    return JevResult(model=str(data.get("model") or "unknown"), answers=answers,
                     state_hash=state_hash,
                     input_tokens=tokens if isinstance(tokens, int) and tokens >= 0 else None)


def request_body(model: str, state: str, questions: dict[str, Question]) -> dict[str, Any]:
    return {"model": model, "state": state,
            "questions": {k: to_wire(q) for k, q in sorted(questions.items())}}


def cache_key(body: dict[str, Any]) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def estimate_tokens(body: dict[str, Any]) -> int:
    return max(1, len(json.dumps(body, ensure_ascii=False)) // 4)


class JevClient:
    def __init__(
        self,
        api_key: str | None,
        *,
        model: str = "jev-1.13",
        base_url: str = DEFAULT_BASE_URL,
        extra_headers: dict[str, str] | None = None,
        timeout_s: float = 3.0,
        cache_dir: Path | None = None,
        daily_token_budget: int = 0,
        http_factory: Callable[[], httpx.Client] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.url = base_url.rstrip("/") + ENDPOINT
        self.extra_headers = dict(extra_headers or {})
        self.timeout_s = timeout_s
        self.cache_dir = cache_dir
        self.daily_token_budget = daily_token_budget
        self._http_factory = http_factory
        self._clock = clock

    @classmethod
    def from_settings(cls, settings: Any, **kw: Any) -> "JevClient":
        return cls(
            settings.jev_api_key,
            model=settings.jev_model,
            base_url=settings.jev_endpoint_base,
            extra_headers=provider_headers(settings.jev_provider),
            timeout_s=settings.jev_timeout_s,
            cache_dir=settings.cache_dir / "jev",
            daily_token_budget=settings.jev_daily_token_budget,
            **kw,
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    # --- cache ----------------------------------------------------------

    def _cache_path(self, key: str) -> Path | None:
        return self.cache_dir / f"{key}.json" if self.cache_dir else None

    def _cache_get(self, key: str) -> JevResult | None:
        path = self._cache_path(key)
        if not path or not path.exists():
            return None
        try:
            if self._clock() - path.stat().st_mtime > CACHE_TTL_S:
                return None
            return JevResult.from_dict(json.loads(path.read_text("utf-8")), cached=True)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _cache_put(self, key: str, result: JevResult) -> None:
        path = self._cache_path(key)
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result.to_dict()), encoding="utf-8")
        except OSError:
            pass

    # --- budget ---------------------------------------------------------

    def _ledger_path(self) -> Path | None:
        if not self.cache_dir:
            return None
        day = datetime.fromtimestamp(self._clock(), timezone.utc).strftime("%Y%m%d")
        return self.cache_dir / f"usage-{day}.json"

    def tokens_used_today(self) -> int:
        path = self._ledger_path()
        if not path or not path.exists():
            return 0
        try:
            return int(json.loads(path.read_text("utf-8")).get("tokens", 0))
        except (OSError, ValueError):
            return 0

    def _charge(self, tokens: int) -> None:
        path = self._ledger_path()
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"tokens": self.tokens_used_today() + tokens}),
                            encoding="utf-8")
        except OSError:
            pass

    # --- the call -------------------------------------------------------

    def ask(self, state: str, questions: dict[str, Question]) -> JevResult:
        if not questions:
            raise ValueError("ask() needs at least one question")
        body = request_body(self.model, state, questions)
        key = cache_key(body)
        hit = self._cache_get(key)
        if hit:
            return hit
        if not self.configured:
            raise JevUnavailable("UMBRA_TYPESAFE_API_KEY is not set")

        tokens = estimate_tokens(body)
        if self.daily_token_budget and self.tokens_used_today() + tokens > self.daily_token_budget:
            raise JevUnavailable("daily Jev token budget spent")

        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json", **self.extra_headers}
        try:
            with self._client() as http:
                resp = http.post(self.url, json=body, headers=headers, timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            raise JevUnavailable(f"transport: {type(exc).__name__}") from exc
        except Exception as exc:  # http_guard.BlockedAddress and friends
            raise JevUnavailable(f"egress refused: {exc}") from exc
        if resp.status_code != 200:
            self._charge(tokens)
            raise JevUnavailable(f"HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            self._charge(tokens)
            raise JevUnavailable("response is not JSON") from exc
        try:
            result = parse_response(data, questions, state_hash=key)
        except JevUnavailable:
            self._charge(tokens)
            raise
        # Bill what the provider says it used; the estimate only when it is silent.
        self._charge(result.input_tokens if result.input_tokens is not None else tokens)
        self._cache_put(key, result)
        return result

    def _client(self) -> httpx.Client:
        if self._http_factory:
            return self._http_factory()
        from umbra.core.http_guard import GuardedClient
        return GuardedClient()
