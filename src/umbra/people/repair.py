"""Clear prose-derived person fields the old parser invented.

`grow.seed_extracts` ran `parse_obituary_text()` over Wikipedia article prose.
An obituary parser looks for "of Boca Raton" and "survived by"; encyclopedia
prose has neither, so the residence pattern matched whatever followed a similar
shape. Prod, before this: 95% of 12,001 people had a `residence`, including
'The Manhattan Transfer', 'ARP Instruments', 'Cuba from', 'New York in' and
"Andy Warhol's underground films filmed at". `occupation` was 10% populated with
truncated sentences.

These are not *degraded* facts, they are non-facts, and that is what makes them
worth clearing rather than leaving for the claims pass to overwrite: a later
pass cannot distinguish an invented value from a real one, so it would either
skip the row (keeping the garbage) or overwrite good data elsewhere.

Only the two fields the obituary parser guessed at are touched. Names, dates,
sources and kinship are left alone — they were not produced by the failing
regex.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

#: A residence is a place name: a few words, no sentence punctuation, no
#: trailing preposition. Anything else came out of prose.
_PROSE_TAIL = re.compile(r"\b(and|for|in|at|from|with|the|his|her|by|of|to|on)$", re.I)

#: An occupation from the old parser is a clause. A real one is a noun phrase.
_MAX_OCCUPATION_WORDS = 6
_MAX_RESIDENCE_WORDS = 5


def looks_like_prose(value: str | None, *, max_words: int) -> bool:
    """True when a field value is a sentence fragment rather than a value.

    Deliberately conservative on the side of *keeping* data: 'Los Angeles' and
    'St. Louis' must survive, so a short capitalised phrase with no sentence
    punctuation is left alone even if it is in fact wrong. The aim is to remove
    what is provably not a place or a job, not to guess at correctness.
    """
    if not value:
        return False
    text = value.strip()
    if not text:
        return False
    words = text.split()
    if len(words) > max_words:
        return True
    # A sentence ended inside the value: "…to detect. His".
    #
    # Not a bare `[.!?]\s`: that fires on "St. Louis" and deletes a real city.
    # An abbreviation is a short token ending in a period, so the boundary only
    # counts when the token before it is a whole word.
    if re.search(r"[a-z]{3,}[.!?]\s+\S", text):
        return True
    # Dangling preposition/conjunction: 'Cuba from', 'New York in', 'Fame in'.
    if _PROSE_TAIL.search(text):
        return True
    # No comma rule. "singer, actor, musician" is exactly the shape
    # `to_parse_dict` writes for a multi-valued P106, so counting commas would
    # delete the good data this repair exists to make room for.
    return False


def repair_prose_fields(*, apply: bool = False, settings: Any = None) -> dict:
    """Null out residence/occupation values that are prose. Dry run by default.

    Returns counts either way, so the dry run reports exactly what the write
    would do rather than an estimate.
    """
    from umbra.core.config import get_settings
    from umbra.lake.people import PeopleLake

    settings = settings or get_settings()
    lake = PeopleLake.from_settings(settings)
    residence = occupation = 0
    total = 0
    try:
        rows = lake._conn.execute(
            "SELECT id, residence, occupation FROM people"
        ).fetchall()
        total = len(rows)
        to_clear_res: list[str] = []
        to_clear_occ: list[str] = []
        for row in rows:
            pid = row[0]
            if looks_like_prose(row[1], max_words=_MAX_RESIDENCE_WORDS):
                to_clear_res.append(pid)
            if looks_like_prose(row[2], max_words=_MAX_OCCUPATION_WORDS):
                to_clear_occ.append(pid)
        residence, occupation = len(to_clear_res), len(to_clear_occ)

        if apply:
            with lake._lock:
                for pid in to_clear_res:
                    lake._conn.execute(
                        "UPDATE people SET residence = NULL WHERE id = ?", (pid,))
                for pid in to_clear_occ:
                    lake._conn.execute(
                        "UPDATE people SET occupation = NULL WHERE id = ?", (pid,))
                lake._conn.commit()
            logger.info("people repair cleared residence=%d occupation=%d",
                        residence, occupation)
    finally:
        lake.close()

    return {
        "people": total,
        "residence": residence,
        "occupation": occupation,
        "applied": apply,
    }
