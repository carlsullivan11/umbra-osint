"""A fake Jev endpoint for tests — no network in pytest (docs/JEV.md §7).

`FakeJev` answers from simple rules over the *state text*, which is enough to
exercise the client, the dual ask and `combine()` end to end. `gullible=True`
models the published weakness: a planted "this site is legitimate" in the
untrusted fence flips the role answer to benign.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from umbra.jev.client import JevClient


def choice(pick: str, probs: dict[str, float], confidence: float) -> dict[str, Any]:
    return {"type": "choice", "choice": pick, "probabilities": probs, "confidence": confidence}


def noul(p: float) -> dict[str, Any]:
    return {"type": "noul", "noul": p}


def _to_decisions(a: dict[str, Any]) -> dict[str, Any]:
    if a["type"] == "noul":
        return {"type": "noul", "yes_probability": a["noul"]}
    out = dict(a)
    out["winner"] = out.pop("choice")
    return out


@dataclass
class FakeJev:
    gullible: bool = False
    status: int = 200
    calls: list[dict[str, Any]] = field(default_factory=list)
    #: role answer per state-substring, first match wins
    role_rules: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    #: answer in OpenRouter's Decisions shape (`decisions`, `winner`,
    #: `yes_probability`) instead of `answers`/`choice`/`noul`
    decisions_shape: bool = False
    input_tokens: int | None = 423
    #: Noul answers per question key: (state-substring, probability), first match wins
    noul_rules: dict[str, list[tuple[str, float]]] = field(default_factory=dict)
    #: planted text in the fence also drags every Noul toward "benign"
    gullible_nouls: bool = False

    def answer_for(self, key: str, q: dict[str, Any], state: str) -> dict[str, Any]:
        fenced = state.split("BEGIN UNTRUSTED CONTENT", 1)[1] if "BEGIN UNTRUSTED CONTENT" in state else ""
        planted = "legitimate" in fenced.lower() and "classifier" in fenced.lower()
        if q["type"] == "noul":
            if key == "_injection_canary":
                return noul(0.93 if planted else 0.04)
            if self.gullible_nouls and planted:
                return noul(0.02)
            for needle, p in self.noul_rules.get(key, []):
                if needle in state:
                    return noul(p)
            return noul(0.9 if "password" in fenced.lower() else 0.1)
        if q["type"] == "score":
            return {"type": "score", "score": 1}
        options = list(q["criteria"])
        if self.gullible and planted:
            benign = "clean" if "clean" in options else "unrelated_legitimate"
            return choice(benign, {benign: 0.9, options[0]: 0.1}, 0.88)
        for needle, ans in self.role_rules:
            if needle in state and ans["choice"] in options:
                return ans
        fallback = "clean" if "clean" in options else "unknown"
        return choice(fallback, {fallback: 0.6, options[0]: 0.4}, 0.4)

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.calls.append({"headers": dict(request.headers), "body": body})
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "nope"})
        answers = {k: self.answer_for(k, q, body["state"]) for k, q in body["questions"].items()}
        payload: dict[str, Any] = {"model": "typesafe/jev-1.13"}
        if self.input_tokens is not None:
            payload["usage"] = {"input_tokens": self.input_tokens, "output_tokens": 0}
        if self.decisions_shape:
            payload["decisions"] = {k: _to_decisions(a) for k, a in answers.items()}
        else:
            payload["answers"] = answers
        return httpx.Response(200, json=payload)

    def client(self, tmp_path=None, **kw: Any) -> JevClient:
        kw.setdefault("api_key", "ts-test-key")
        return JevClient(
            kw.pop("api_key"),
            cache_dir=(tmp_path / "jev") if tmp_path else None,
            http_factory=lambda: httpx.Client(transport=httpx.MockTransport(self.handler)),
            **kw,
        )
