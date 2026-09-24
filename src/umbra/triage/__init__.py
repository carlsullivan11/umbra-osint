"""SOC-style alert triage: Umbra investigates, Jev makes the call, a person decides.

docs/TRIAGE.md · docs/JEV-SOC.md · docs/JEV-EVAL.md. Bring your own Jev key;
without one, triage runs on Umbra's deterministic checks alone.
"""
from umbra.triage.alert import Alert, Indicator, parse_input
from umbra.triage.disposition import ESCALATE, NEEDS_ANALYST, SUGGEST_CLOSE, Decision, decide
from umbra.triage.engine import AlertResult, assess, enrich, triage_collectors

__all__ = [
    "Alert", "AlertResult", "Decision", "ESCALATE", "Indicator", "NEEDS_ANALYST",
    "SUGGEST_CLOSE", "assess", "decide", "enrich", "parse_input", "triage_collectors",
]
