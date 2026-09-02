"""Obituary text parsing — survivors, dates, places, funeral metadata.

Designed for a **wide variety** of U.S. funeral-notice styles (Legacy, local
papers, Find a Grave bios, Dignity, Echovita). Output is structured and
conservative: every kinship hit carries an evidence span; bare given names are
only promoted with decedent surname after spouse/child cues.

Not perfect NLP — intentionally regex/heuristic so it stays offline, fast, and
testable. Human confirm remains required for identity.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class KinPerson:
    name: str
    role: str = "unknown"  # spouse, child, sibling, parent, grandchild, in_law, extended, preceded, unknown
    evidence_span: str = ""
    living: bool = True  # False = preceded in death


@dataclass
class ObituaryParse:
    """Structured fields extracted from one notice body + optional title."""

    decedent_name: str = ""
    age: int | None = None
    birth_date: str | None = None
    death_date: str | None = None
    birth_place: str | None = None
    death_place: str | None = None
    residence: str | None = None  # "of City, ST" / formerly of
    occupation: str | None = None
    funeral_home: str | None = None
    cemetery: str | None = None
    service_info: str | None = None
    military: str | None = None
    survivors: list[KinPerson] = field(default_factory=list)
    preceded: list[KinPerson] = field(default_factory=list)
    aka: list[str] = field(default_factory=list)
    raw_survivor_clauses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --- name / role patterns -------------------------------------------------

_ROLE_WORD: list[tuple[str, re.Pattern[str]]] = [
    # in_law before child/parent so "daughter-in-law" ≠ child
    ("in_law", re.compile(
        r"\b(?:son-in-law|daughter-in-law|brother-in-law|sister-in-law|"
        r"mother-in-law|father-in-law|in-laws?)\b", re.I)),
    ("spouse", re.compile(
        r"\b(?:beloved\s+)?(?:wife|husband|spouse|partner|widow|widower|"
        r"fiancé|fiance|fiancée|companion)\b", re.I)),
    ("grandchild", re.compile(
        r"\b(?:grandson|granddaughter|grandchild(?:ren)?|great-?grand(?:son|daughter|child(?:ren)?))\b", re.I)),
    ("child", re.compile(
        r"\b(?:step-?son|step-?daughter|step-?child(?:ren)?|son|daughter|child|children)\b", re.I)),
    ("sibling", re.compile(
        r"\b(?:step-?brother|step-?sister|brother|sister|sibling)\b", re.I)),
    ("parent", re.compile(
        r"\b(?:stepmother|stepfather|mother|father|parent|mom|dad)\b", re.I)),
    ("extended", re.compile(
        r"\b(?:niece|nephew|uncle|aunt|cousin|god(?:son|daughter|child)|"
        r"friend|companion)\b", re.I)),
]

# Multi-token names including hyphens, apostrophes, particles (de, van, Mc)
_NAME_RE = re.compile(
    r"\b("
    r"(?:Mc|Mac|O')?[A-Z][a-z]+(?:['-][A-Z][a-z]+)*"
    r"(?:\s+(?:van|von|de|del|della|di|da|la|le|st\.?|saint)\s+)?"
    r"(?:\s+(?:Mc|Mac|O')?[A-Z][a-z]+(?:['-][A-Z][a-z]+)*)+"
    r")\b"
)

_GIVEN_RE = re.compile(r"\b((?:Mc|Mac|O')?[A-Z][a-z]+(?:['-][A-Z][a-z]+)*)\b")

_NAME_BLOCKLIST = {
    "United States", "New York", "San Francisco", "Los Angeles", "Las Vegas",
    "Funeral Home", "Memorial Chapel", "Catholic Church", "Baptist Church",
    "Methodist Church", "Lutheran Church", "High School", "University Of",
    "View Obituary", "Leave Condolence", "Share Obituary", "Guest Book",
    "In Memory", "Celebration Of", "Order Flowers", "Send Flowers",
    "Online Condolences", "Memorial Service", "Funeral Service",
    "Visitation Will", "Graveside Service", "Mass Of", "Rosary Will",
    "Monday Morning", "Tuesday Morning", "Wednesday Morning",
    "Thursday Morning", "Friday Morning", "Saturday Morning", "Sunday Morning",
    "January", "February", "March", "April", "June", "July", "August",
    "September", "October", "November", "December",
}

# Clauses that introduce living survivors
_SURVIVOR_CLAUSE = re.compile(
    r"(?:"
    r"is\s+survived\s+by|"
    r"was\s+survived\s+by|"
    r"survived\s+by|"
    r"survivors?\s+(?:include|are|were)|"
    r"leaves?\s+behind|"
    r"lovingly\s+remembered\s+by|"
    r"mourned\s+by|"
    r"will\s+be\s+missed\s+by|"
    r"dearly\s+missed\s+by"
    r")\s*[:\-]?\s*(.+?)(?:"
    r"(?:he|she)\s+was\s+preceded|"
    r"preceded\s+in\s+death|"
    r"funeral\s+(?:service|mass|arrangements)|"
    r"services?\s+(?:will|are)|"
    r"visitation|"
    r"in\s+lieu\s+of|"
    r"memorials?\s+may|"
    r"interment|"
    r"burial|"
    r"$)",
    re.I | re.S,
)

_PRECEDED_CLAUSE = re.compile(
    r"(?:"
    r"preceded\s+in\s+death\s+by|"
    r"was\s+preceded\s+in\s+death\s+by|"
    r"predeceased\s+by"
    r")\s*[:\-]?\s*(.+?)(?:"
    r"is\s+survived|"
    r"survived\s+by|"
    r"funeral|"
    r"services?|"
    r"visitation|"
    r"in\s+lieu|"
    r"$)",
    re.I | re.S,
)

# Loving husband of X / devoted wife of Y
_OF_SPOUSE = re.compile(
    r"\b(?:loving|devoted|beloved)?\s*(?:husband|wife|spouse)\s+of\s+"
    r"([A-Z][^,.;]{1,60}?)(?:,|\.|$|\s+and\b)",
    re.I,
)

_AGE_RE = re.compile(
    r"\b(?:age[d]?\s+)?(\d{1,3})\s*(?:years?\s+old|years?\s+of\s+age)?\b|"
    r"\((\d{1,3})\)",
    re.I,
)

_DATE_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4}\b|"
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|"
    r"\b\d{4}-\d{2}-\d{2}\b",
    re.I,
)

_BORN_RE = re.compile(
    r"\b(?:born|birth)\s+(?:on\s+)?([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
    re.I,
)
_DIED_RE = re.compile(
    r"\b(?:died|passed\s+away|went\s+to\s+be\s+with|entered\s+(?:into\s+)?rest|"
    r"departed\s+this\s+life)\s+(?:on\s+|peacefully\s+(?:on\s+)?)?"
    r"([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
    re.I,
)
_OF_PLACE_RE = re.compile(
    r"\bof\s+([A-Z][A-Za-z .'-]{2,40}(?:,\s*[A-Z]{2})?)\b",
)
_FORMERLY_RE = re.compile(
    r"\bformerly\s+of\s+([A-Z][A-Za-z .'-]{2,40}(?:,\s*[A-Z]{2})?)",
    re.I,
)
_PASSED_IN_RE = re.compile(
    r"\b(?:passed\s+away|died)\s+(?:peacefully\s+)?(?:at|in)\s+"
    r"([A-Z][A-Za-z .'-]{2,50})",
    re.I,
)
_FUNERAL_HOME_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z&'.-]+(?:\s+[A-Z][A-Za-z&'.-]+){0,4})\s+"
    r"(?:Funeral\s+Home|Mortuary|Funeral\s+Chapel|Memorial\s+(?:Home|Chapel|Services?)))\b",
)
_CEMETERY_RE = re.compile(
    r"\b(?:interment|burial|laid\s+to\s+rest|cemetery)\s*(?:at|in|:)?\s*"
    r"([A-Z][A-Za-z &'.-]{2,60}(?:Cemetery|Memorial\s+Park|Gardens?))",
    re.I,
)
_OCCUPATION_RE = re.compile(
    r"\b(?:worked\s+(?:as|for)|retired\s+(?:from|as)|career\s+(?:as|with|in)|"
    r"employed\s+(?:as|by|with))\s+([^.]{5,80})",
    re.I,
)
_MILITARY_RE = re.compile(
    r"\b((?:U\.?S\.?\s+)?(?:Army|Navy|Air\s+Force|Marine\s+Corps|Coast\s+Guard|"
    r"Space\s+Force|National\s+Guard|veteran)[^.]{0,60})",
    re.I,
)
_AKA_RE = re.compile(
    r"\b(?:known\s+as|nicknamed|aka|a\.k\.a\.)\s+[\"']?([A-Z][A-Za-z .'-]{1,40})[\"']?",
    re.I,
)


def _norm_ws(text: str) -> str:
    t = (
        text.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\xa0", " ")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
    )
    return re.sub(r"\s+", " ", t).strip()


def _role_in(text: str) -> str:
    for role, cre in _ROLE_WORD:
        if cre.search(text):
            return role
    return "unknown"


def _good_name(nm: str, decedent_l: str) -> bool:
    if not nm or len(nm) < 3:
        return False
    if nm.lower() == decedent_l:
        return False
    if nm in _NAME_BLOCKLIST:
        return False
    # reject pure month/day noise
    if nm.split()[0] in _NAME_BLOCKLIST:
        return False
    if len(nm.split()) > 5:
        return False
    # must have at least one space for multi-token unless later bare-name path
    return True


def _split_list_clause(span: str) -> list[str]:
    # Split on ; , and "and" but keep "and" inside names rarely - standard approach
    parts = re.split(r"\s*;\s*|\s*,\s*|\s+and\s+|\s+as\s+well\s+as\s+", span, flags=re.I)
    return [p.strip(" .") for p in parts if p.strip(" .")]


def _extract_names_from_clause(
    span: str,
    decedent_name: str,
    *,
    default_role: str = "unknown",
    living: bool = True,
) -> list[KinPerson]:
    decedent_l = decedent_name.strip().lower()
    parts = decedent_name.strip().split()
    surname = parts[-1] if len(parts) >= 2 else ""
    out: list[KinPerson] = []
    seen: set[str] = set()

    current_role = default_role
    for chunk in _split_list_clause(span):
        if not chunk:
            continue
        role = _role_in(chunk)
        if role != "unknown":
            current_role = role

        found_multi = False
        for nm in _NAME_RE.findall(chunk):
            if not _good_name(nm, decedent_l):
                continue
            key = nm.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(
                KinPerson(
                    name=nm,
                    role=current_role if current_role != "unknown" else role,
                    evidence_span=span[:280],
                    living=living,
                )
            )
            found_multi = True

        # Bare given after spouse/child cue: "wife Laurene" / "son Reed"
        if surname and current_role in {"spouse", "child", "parent", "grandchild"}:
            for m in re.finditer(
                r"\b(?:wife|husband|spouse|son|daughter|mother|father|"
                r"grandson|granddaughter)\s+([A-Z][a-z]+)\b",
                chunk,
            ):
                given = m.group(1)
                full = f"{given} {surname}"
                if full.lower() == decedent_l or full.lower() in seen:
                    continue
                if given.lower() in {p.lower() for p in parts}:
                    continue
                if given in _NAME_BLOCKLIST:
                    continue
                # If multi-name already captured this given as start, skip
                if any(k.startswith(given.lower() + " ") for k in seen):
                    continue
                seen.add(full.lower())
                out.append(
                    KinPerson(
                        name=full,
                        role=current_role,
                        evidence_span=span[:280],
                        living=living,
                    )
                )
                found_multi = True

        # "three children, Erin, Reed and Eve" — bare given list after children
        if surname and current_role == "child" and not found_multi:
            givens = _GIVEN_RE.findall(chunk)
            # filter role words capitalized wrongly
            skip = {
                "Son", "Daughter", "Children", "Child", "Brother", "Sister",
                "Wife", "Husband", "Mother", "Father", "Grandson", "Granddaughter",
            }
            for g in givens:
                if g in skip or g in _NAME_BLOCKLIST:
                    continue
                full = f"{g} {surname}"
                if full.lower() in seen or full.lower() == decedent_l:
                    continue
                seen.add(full.lower())
                out.append(
                    KinPerson(
                        name=full,
                        role="child",
                        evidence_span=span[:280],
                        living=living,
                    )
                )

    return out


def parse_obituary_text(
    text: str,
    *,
    decedent_name: str = "",
    title: str | None = None,
) -> ObituaryParse:
    """Parse free-text obituary / memorial body into structured fields."""
    raw = _norm_ws((title or "") + "\n" + (text or ""))
    result = ObituaryParse(decedent_name=decedent_name.strip())

    if not raw:
        return result

    # Decedent from title if missing: "John Q. Public Obituary"
    if not result.decedent_name and title:
        tm = re.match(
            r"^([A-Z][^|–\-]+?)(?:\s+Obituary|\s+Obit|\s+\(|$)",
            title.strip(),
        )
        if tm:
            result.decedent_name = tm.group(1).strip()

    name = result.decedent_name

    # Age — prefer "aged 72" / "72 years old" / ", 84," near start
    head = raw[:500]
    am = re.search(
        r"\b(?:aged?\s+)(\d{1,3})\b|"
        r"\b(\d{1,3})\s+years?\s+old\b|"
        r"\((\d{1,3})\)|"
        r",\s*(\d{1,3})\s*,",
        head,
        re.I,
    )
    if am:
        g = next(x for x in am.groups() if x)
        age = int(g)
        if 1 <= age <= 120:
            result.age = age

    bm = _BORN_RE.search(raw)
    if bm:
        result.birth_date = bm.group(1)
    dm = _DIED_RE.search(raw)
    if dm:
        result.death_date = dm.group(1)
    # lifespan in title "1955-2011"
    if title:
        lm = re.search(r"\((\d{4})\s*[-–]\s*(\d{4})\)", title)
        if lm:
            result.birth_date = result.birth_date or lm.group(1)
            result.death_date = result.death_date or lm.group(2)

    fm = _FORMERLY_RE.search(raw)
    if fm:
        result.residence = fm.group(1).strip(" ,")
    om = _OF_PLACE_RE.search(raw[:500])
    if om and not result.residence:
        place = om.group(1).strip(" ,")
        if place.lower() not in {x.lower() for x in _NAME_BLOCKLIST}:
            result.residence = place

    pm = _PASSED_IN_RE.search(raw)
    if pm:
        result.death_place = pm.group(1).strip(" ,")[:80]

    fh = _FUNERAL_HOME_RE.search(raw)
    if fh:
        result.funeral_home = fh.group(1).strip()
    cm = _CEMETERY_RE.search(raw)
    if cm:
        result.cemetery = cm.group(1).strip()

    occ = _OCCUPATION_RE.search(raw)
    if occ:
        result.occupation = occ.group(1).strip(" ,")[:120]
    mil = _MILITARY_RE.search(raw)
    if mil:
        result.military = mil.group(1).strip(" ,")[:120]

    for m in _AKA_RE.finditer(raw):
        aka = m.group(1).strip()
        if aka and aka not in result.aka:
            result.aka.append(aka)

    # Service blurb
    sm = re.search(
        r"((?:funeral|memorial|graveside|mass|visitation)\s+"
        r"(?:service|services|will be|is scheduled)[^.]{10,160}\.)",
        raw,
        re.I,
    )
    if sm:
        result.service_info = sm.group(1).strip()[:240]

    # Loving husband of ...
    for m in _OF_SPOUSE.finditer(raw):
        spouse = m.group(1).strip(" ,")
        # take leading name tokens
        nm = _NAME_RE.search(spouse) or None
        spouse_name = nm.group(1) if nm else spouse.split(" of ")[0].strip()
        if _good_name(spouse_name, name.lower()) or (
            name and len(spouse_name.split()) == 1
        ):
            if len(spouse_name.split()) == 1 and name:
                spouse_name = f"{spouse_name} {name.split()[-1]}"
            result.survivors.append(
                KinPerson(
                    name=spouse_name,
                    role="spouse",
                    evidence_span=m.group(0)[:280],
                    living=True,
                )
            )

    # Wikipedia / biography style: "married X", "wife Y", "children A, B and C"
    for m in re.finditer(
        r"\b(?:married|wed)\s+(?:to\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b",
        raw,
    ):
        sn = m.group(1).strip()
        if _good_name(sn, name.lower()) or (name and " " not in sn):
            if " " not in sn and name:
                # keep bare only if multi-token later; skip single unless already known
                pass
            if " " in sn and sn.lower() != name.lower():
                result.survivors.append(
                    KinPerson(name=sn, role="spouse", evidence_span=m.group(0)[:280], living=True)
                )
    for m in re.finditer(
        r"\b(?:his|her)\s+(?:first\s+|second\s+)?(?:wife|husband)\s*,?\s+"
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b",
        raw,
    ):
        sn = m.group(1).strip()
        if " " in sn and sn.lower() != name.lower():
            result.survivors.append(
                KinPerson(name=sn, role="spouse", evidence_span=m.group(0)[:280], living=True)
            )
    for m in re.finditer(
        r"\b(?:their|his|her)\s+(?:two|three|four|five|\d+)?\s*children[,\s]+"
        r"([A-Z][^.]{5,120}?)(?:\.|$)",
        raw,
        re.I,
    ):
        clause = m.group(1)
        result.raw_survivor_clauses.append(clause[:500])
        result.survivors.extend(
            _extract_names_from_clause(
                "children " + clause, name or "Unknown Person", living=True
            )
        )
    for m in re.finditer(
        r"\b(?:father|mother|parents)\s+(?:were|was)\s+([A-Z][^.]{5,100}?)(?:\.|$)",
        raw,
        re.I,
    ):
        clause = m.group(1)
        result.preceded.extend(
            _extract_names_from_clause(
                "parents " + clause,
                name or "Unknown Person",
                living=False,
                default_role="parent",
            )
        )
    for m in re.finditer(
        r"\b(?:his|her)\s+(?:younger\s+|older\s+|half[- ])?(?:sister|brother)\s+"
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b",
        raw,
    ):
        sn = m.group(1).strip()
        if " " in sn and sn.lower() != name.lower():
            result.survivors.append(
                KinPerson(name=sn, role="sibling", evidence_span=m.group(0)[:280], living=True)
            )

    # Survivor clauses
    for m in _SURVIVOR_CLAUSE.finditer(raw):
        clause = m.group(1).strip()
        if len(clause) < 3:
            continue
        result.raw_survivor_clauses.append(clause[:500])
        result.survivors.extend(
            _extract_names_from_clause(clause, name or "Unknown Person", living=True)
        )

    # Preceded in death
    for m in _PRECEDED_CLAUSE.finditer(raw):
        clause = m.group(1).strip()
        if len(clause) < 3:
            continue
        result.preceded.extend(
            _extract_names_from_clause(
                clause, name or "Unknown Person", living=False, default_role="preceded"
            )
        )

    # Dedupe survivors by lower name (keep richer role)
    def _dedupe(people: list[KinPerson]) -> list[KinPerson]:
        best: dict[str, KinPerson] = {}
        for p in people:
            k = p.name.lower()
            if k not in best:
                best[k] = p
                continue
            # prefer non-unknown role
            if best[k].role == "unknown" and p.role != "unknown":
                best[k] = p
            elif p.role != "unknown" and len(p.name) > len(best[k].name):
                best[k] = p
        return list(best.values())[:40]

    result.survivors = _dedupe(result.survivors)
    result.preceded = _dedupe(result.preceded)
    return result


def strip_html(html: str) -> str:
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"(?is)<noscript[^>]*>.*?</noscript>", " ", t)
    t = re.sub(r"<[^>]+>", " ", t)
    return _norm_ws(t)
