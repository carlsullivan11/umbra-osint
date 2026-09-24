"""Jev (TypeSafe AI) as a second opinion on "is this malicious?" — docs/JEV.md.

Off by default. Umbra's deterministic verdict stays authoritative; `combine`
is the only function that lets a Jev answer touch it.
"""
from umbra.jev.adjudicate import adjudicate, adjudicate_case
from umbra.jev.client import Answer, JevClient, JevResult, JevUnavailable
from umbra.jev.combine import Adjudication, combine
from umbra.jev.facts import Facts, facts_from_props, render_state

__all__ = [
    "Adjudication", "Answer", "Facts", "JevClient", "JevResult", "JevUnavailable",
    "adjudicate", "adjudicate_case", "combine", "facts_from_props", "render_state",
]
