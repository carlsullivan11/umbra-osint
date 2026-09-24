"""Name matching for the people lake.

The previous scheme normalised a name to `" ".join(name.lower().split())` and
looked it up with `norm_name = ? OR norm_name LIKE ? OR full_name LIKE ?`. That
has two failures, and the second gets worse as the corpus grows.

**It only matches what you typed.** "Ruth Bader Ginsburg" finds her;
"Ginsburg, Ruth", "R. B. Ginsburg", "Ruth Ginsburg", and "José García" typed
without the accent all miss. An investigator does not know the stored spelling
— not knowing it is why they are searching.

**`LIKE '%x%'` cannot use an index.** Invisible at 12k rows. At the 454,614 this
lake is heading for, every search becomes a full table scan.

So a name is reduced to a canonical form, expanded into the handful of variants
someone might actually type, and those variants are stored as indexed keys.
Lookup becomes an equality join, and each key carries how strong a match it
represents — an exact hit and a dropped-middle-name hit are both worth
returning, and must not be presented as the same thing.

What is deliberately *not* done: no phonetic matching (Soundex/Metaphone). It
collapses genuinely different surnames together, and on a person search a false
match is a claim about someone who has nothing to do with the query.
"""
from __future__ import annotations

import re
import unicodedata
from enum import Enum

#: Generational and professional suffixes. Dropped because they are how a
#: record was typed, not how a searcher distinguishes two people.
_SUFFIXES = {
    "jr", "sr", "ii", "iii", "iv", "v",
    "md", "phd", "dds", "esq", "jd", "rn", "dvm", "do", "cpa", "mba",
}

#: Common English given-name short forms, both directions. Deliberately small
#: and hand-checked: a wrong entry here silently merges two people, so this is
#: a place to be conservative rather than comprehensive.
_NICKNAMES: dict[str, set[str]] = {
    "robert": {"bob", "rob", "bobby"},
    "william": {"bill", "will", "billy"},
    "richard": {"rick", "dick", "richie"},
    "james": {"jim", "jimmy"},
    "john": {"jack", "johnny"},
    "joseph": {"joe", "joey"},
    "michael": {"mike", "mikey"},
    "charles": {"charlie", "chuck"},
    "thomas": {"tom", "tommy"},
    "christopher": {"chris"},
    "daniel": {"dan", "danny"},
    "matthew": {"matt"},
    "anthony": {"tony"},
    "edward": {"ed", "eddie", "ted"},
    "margaret": {"peggy", "maggie"},
    "elizabeth": {"liz", "beth", "betty", "eliza"},
    "katherine": {"kate", "kathy", "katie"},
    "catherine": {"cathy", "kate"},
    "patricia": {"pat", "patty", "tricia"},
    "jennifer": {"jen", "jenny"},
    "deborah": {"deb", "debbie"},
    "barbara": {"barb", "babs"},
    "susan": {"sue", "susie"},
    "rebecca": {"becky", "becca"},
    "theodore": {"ted", "teddy"},
    "andrew": {"andy", "drew"},
    "benjamin": {"ben", "benny"},
    "samuel": {"sam", "sammy"},
    "nicholas": {"nick"},
    "alexander": {"alex", "sandy"},
}

#: Prefix for surname-only keys. Namespaced so a bare surname can never collide
#: with a one-word full name — "Cher" is a person, "cher" as a surname is not
#: the same claim.
SURNAME_PREFIX = "~sn:"

#: Bumped whenever `name_keys` changes what it emits. The lake stores the
#: version it indexed at and rebuilds on mismatch — otherwise a lake indexed by
#: older code keeps answering with the old key set and the only symptom is
#: results that quietly do not appear.
#:   1  full / first+last / initial+last / nickname variants
#:   2  + namespaced surname keys for a bare-surname browse
NAME_KEY_VERSION = 2

#: Reverse index, built once. A short form can map to several formal names
#: ("kate" -> katherine, catherine), and all of them are produced.
_FROM_NICK: dict[str, set[str]] = {}
for _formal, _shorts in _NICKNAMES.items():
    for _s in _shorts:
        _FROM_NICK.setdefault(_s, set()).add(_formal)


class MatchStrength(str, Enum):
    """How a key matched, so a caller can rank and label results."""

    EXACT = "exact"        # every token, in order
    PARTIAL = "partial"    # first + last, middle names dropped
    WEAK = "weak"          # first initial + last
    SURNAME = "surname"    # a bare surname: a browse, not an identification


def _fold(text: str) -> str:
    """Strip diacritics: the record has the accent, the keyboard does not."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def canonical(raw: str | None) -> str:
    """A name reduced to lowercase ASCII words, suffixes and titles removed.

    Handles the "Ginsburg, Ruth Bader" form that government and funeral records
    use — but only when the comma really is a reversal. "John Smith, MD" has a
    comma and is not reversed, which is why suffix stripping happens first.
    """
    if not raw:
        return ""
    text = _fold(str(raw))
    text = text.replace("'", " ").replace("’", " ")
    text = re.sub(r"[^A-Za-z, ]+", " ", text).lower()

    # Suffixes before reversal: otherwise "Smith, MD" looks like "MD Smith".
    if "," in text:
        head, _, tail = text.partition(",")
        tail_tokens = [t for t in tail.split() if t]
        if tail_tokens and all(t.strip(". ") in _SUFFIXES for t in tail_tokens):
            text = head
        else:
            text = f"{tail} {head}"

    tokens = [t for t in re.split(r"\s+", text) if t and t not in _SUFFIXES]
    return " ".join(tokens)


def split_display(raw: str | None) -> tuple[str, str]:
    """(first, last) from a canonical name. A single token is both."""
    tokens = canonical(raw).split()
    if not tokens:
        return "", ""
    if len(tokens) == 1:
        return tokens[0], tokens[0]
    return tokens[0], tokens[-1]


def _variants(first: str, last: str) -> set[str]:
    """First-name alternatives for `first`, including `first` itself."""
    out = {first}
    out |= _NICKNAMES.get(first, set())
    out |= _FROM_NICK.get(first, set())
    return out


def name_keys(raw: str | None) -> list[str]:
    """Every key under which this name should be findable.

    Written to the index when a person is stored. Order is stable so a rebuild
    produces the same rows.
    """
    norm = canonical(raw)
    if not norm:
        return []
    tokens = norm.split()
    if len(tokens) == 1:
        return [tokens[0], f"{SURNAME_PREFIX}{tokens[0]}"]

    first, last = tokens[0], tokens[-1]
    # Namespaced so it is reachable only by a deliberate surname search, never
    # as a side effect of matching a full name.
    keys: list[str] = [norm, f"{SURNAME_PREFIX}{last}"]
    for alt in sorted(_variants(first, last)):
        # first + last, middle dropped
        keys.append(f"{alt} {last}")
        # initial + last
        keys.append(f"{alt[0]} {last}")
        # the full form with the alternative first name
        if len(tokens) > 2:
            keys.append(" ".join([alt, *tokens[1:]]))

    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def query_keys(raw: str | None) -> list[tuple[str, MatchStrength]]:
    """Keys to look up for a search, strongest first.

    Every key here is one `name_keys` also produces, so a query can only fail
    to match because the person is absent — never because the two sides
    disagree about how to spell a key.
    """
    norm = canonical(raw)
    if not norm:
        return []
    tokens = norm.split()
    if len(tokens) == 1:
        # One token is ambiguous: it may be a mononym ("Cher") or a surname
        # browse ("Franklin"). Both are offered, the exact person first, and
        # the surname hits are labelled as a browse rather than a match.
        return [
            (tokens[0], MatchStrength.EXACT),
            (f"{SURNAME_PREFIX}{tokens[0]}", MatchStrength.SURNAME),
        ]

    first, last = tokens[0], tokens[-1]
    ranked: list[tuple[str, MatchStrength]] = [(norm, MatchStrength.EXACT)]

    for alt in sorted(_variants(first, last)):
        if len(tokens) > 2:
            full_alt = " ".join([alt, *tokens[1:]])
            if full_alt != norm:
                ranked.append((full_alt, MatchStrength.EXACT))
        short = f"{alt} {last}"
        if short != norm:
            ranked.append((short, MatchStrength.PARTIAL))

    for alt in sorted(_variants(first, last)):
        ranked.append((f"{alt[0]} {last}", MatchStrength.WEAK))

    seen: set[str] = set()
    out: list[tuple[str, MatchStrength]] = []
    for key, strength in ranked:
        if key not in seen:
            seen.add(key)
            out.append((key, strength))
    return out


def compare_names(query: str | None, stored: str | None) -> MatchStrength | None:
    """How well `query` matches the person actually found, or None if it does not.

    Strength has to be judged against the *matched record*, not against which
    query key happened to hit. Searching "Ruth Ginsburg" produces the key
    "ruth ginsburg" as an exact rendering of what was typed — but the person it
    finds is "Ruth Bader Ginsburg", and calling that EXACT tells the caller the
    middle name was confirmed when it was dropped.
    """
    q, s_ = canonical(query), canonical(stored)
    if not q or not s_:
        return None
    if q == s_:
        return MatchStrength.EXACT

    qt, st = q.split(), s_.split()
    # A single-token query that is not the whole stored name is a surname
    # browse. Calling it PARTIAL would say the first name was confirmed.
    if len(qt) == 1:
        return MatchStrength.SURNAME if qt[0] == st[-1] else None
    if not qt or not st:
        return None

    q_first, q_last = qt[0], qt[-1]
    s_first, s_last = st[0], st[-1]
    if q_last != s_last:
        return None

    # An initial only ever supports a weak claim, in either direction.
    if len(q_first) == 1 or len(s_first) == 1:
        return MatchStrength.WEAK if q_first[0] == s_first[0] else None

    if q_first == s_first or q_first in _variants(s_first, s_last):
        # Same first and last; middle names differ or are absent.
        return MatchStrength.PARTIAL
    return None
