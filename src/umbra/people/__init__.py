"""People package — person-map helpers (obituary parse, lake access)."""

from umbra.people.obituary_parse import ObituaryParse, KinPerson, parse_obituary_text, strip_html
from umbra.people.graph import graph_from_parse, graph_from_lake, decedent_entity

__all__ = [
    "ObituaryParse",
    "KinPerson",
    "parse_obituary_text",
    "strip_html",
    "graph_from_parse",
    "graph_from_lake",
    "decedent_entity",
]
