"""IntentPlan schema — structured output of free-text intake (Phase I+)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from umbra.core.models import EntityType, new_id


AuthBasis = Literal[
    "own_asset",
    "client_engagement",
    "public_cti",
    "training_lab",
    "other",
]


class IntentFlags(BaseModel):
    want_lookalikes: bool = False
    want_breaches: bool = False
    want_corp_records: bool = False
    aggressive_username_probe: bool = False
    want_web_search: bool = False
    want_wayback: bool = False


class IntentSeed(BaseModel):
    type: EntityType
    value: str
    confidence: float = 0.8
    source_span: str | None = None
    include: bool = True
    notes: str | None = None
    props: dict[str, Any] = Field(default_factory=dict)


class IntentPlan(BaseModel):
    schema_version: int = 1
    plan_id: str = Field(default_factory=lambda: new_id("plan_"))
    case_name: str = "Intent case"
    authorization_basis: AuthBasis = "training_lab"
    authorization_note: str = ""
    summary: str = ""
    seeds: list[IntentSeed] = Field(default_factory=list)
    playbook: str | None = None
    collectors: list[str] = Field(default_factory=list)
    depth: int = 1
    max_entities: int = 500
    flags: IntentFlags = Field(default_factory=IntentFlags)
    warnings: list[str] = Field(default_factory=list)
    clarifying_questions: list[str] = Field(default_factory=list)
    refuse: bool = False
    refuse_reason: str | None = None
    extractor: str = "deterministic_v1"
    raw_intent: str | None = None

    def included_seeds(self) -> list[IntentSeed]:
        return [s for s in self.seeds if s.include]


class AnalyzeRequest(BaseModel):
    text: str
    authorization_basis: AuthBasis = "training_lab"
    authorization_note: str = ""
    case_name: str | None = None
    default_depth: int = 1
    max_entities: int = 500
    # None = follow UMBRA_LLM_ENABLED; True force attempt; False force deterministic
    use_llm: bool | None = None
