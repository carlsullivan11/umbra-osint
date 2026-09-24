"""Structured Wikidata claims for the people lake.

Replaces the previous path, which asked Wikidata for a name and an enwiki title,
then fetched the Wikipedia *article* and ran `parse_obituary_text()` over the
prose. An obituary parser is built for "of Boca Raton … survived by …";
encyclopedia prose says "best known for The Monkees and for his solo work", so
the residence regex returned exactly that string. Measured on prod, that produced
95% residence coverage that was substantially parse debris, 10% occupation that
was truncated sentences, and 0% birth place.

Every one of those fields is a structured claim on the same items the harvest
was already selecting — 454,614 deceased US humans carry both P106 and P19. So
this asks Wikidata for the claims instead of guessing at the article.

Two design constraints shape the query:

**Aggregation.** Occupation, spouse and child are multi-valued. Without
GROUP_CONCAT a person with three occupations and two children returns six rows,
and any caller that does not de-duplicate silently multiplies them.

**A bounded subquery.** WDQS times out at 60 seconds. Selecting the item set in
an inner query with its own LIMIT, then decorating that bounded set with the
OPTIONAL label joins, is what keeps this inside the budget. Decorating first and
limiting afterwards is the shape that times out.

Labels are fetched with explicit `rdfs:label` rather than `SERVICE
wikibase:label`, because the label service does not compose with GROUP BY.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"

#: GROUP_CONCAT separator. A pipe cannot appear in a Wikidata label, so it is
#: safe to split on; a comma is not (occupations like "actor, model" exist).
SEP = "|"

#: WDQS echoes the entity id when a label is missing. "Q7259" stored as an
#: occupation is worse than nothing, because it looks like a real value.
_QID_RE = re.compile(r"^Q\d+$")

PERSON_QUERY = """
SELECT ?item ?itemLabel ?enwiki
       (SAMPLE(?dob) AS ?birth_date)
       (SAMPLE(?dod) AS ?death_date)
       (SAMPLE(?bpl) AS ?birth_place)
       (SAMPLE(?dpl) AS ?death_place)
       (SAMPLE(?res) AS ?residence)
       (GROUP_CONCAT(DISTINCT ?occ; separator="|") AS ?occupations)
       (GROUP_CONCAT(DISTINCT ?emp; separator="|") AS ?employers)
       (GROUP_CONCAT(DISTINCT ?spouse; separator="|") AS ?spouses)
       (GROUP_CONCAT(DISTINCT ?father; separator="|") AS ?fathers)
       (GROUP_CONCAT(DISTINCT ?mother; separator="|") AS ?mothers)
       (GROUP_CONCAT(DISTINCT ?child; separator="|") AS ?children)
WHERE {{
  {{
    SELECT ?item ?itemLabel ?enwiki ?dod WHERE {{
      ?item wdt:P31 wd:Q5 ;
            wdt:P27 wd:Q30 ;
            wdt:P570 ?dod .
      FILTER(YEAR(?dod) >= {year_from} && YEAR(?dod) < {year_to})
      ?sitelink schema:about ?item ;
                schema:isPartOf <https://en.wikipedia.org/> ;
                schema:name ?enwiki .
      ?item rdfs:label ?itemLabel . FILTER(LANG(?itemLabel) = "en")
    }}
    LIMIT {limit}
    OFFSET {offset}
  }}
  OPTIONAL {{ ?item wdt:P569 ?dob . }}
  OPTIONAL {{ ?item wdt:P19 ?bplE . ?bplE rdfs:label ?bpl . FILTER(LANG(?bpl) = "en") }}
  OPTIONAL {{ ?item wdt:P20 ?dplE . ?dplE rdfs:label ?dpl . FILTER(LANG(?dpl) = "en") }}
  OPTIONAL {{ ?item wdt:P551 ?resE . ?resE rdfs:label ?res . FILTER(LANG(?res) = "en") }}
  OPTIONAL {{ ?item wdt:P106 ?occE . ?occE rdfs:label ?occ . FILTER(LANG(?occ) = "en") }}
  OPTIONAL {{ ?item wdt:P108 ?empE . ?empE rdfs:label ?emp . FILTER(LANG(?emp) = "en") }}
  OPTIONAL {{ ?item wdt:P26 ?spE . ?spE rdfs:label ?spouse . FILTER(LANG(?spouse) = "en") }}
  OPTIONAL {{ ?item wdt:P22 ?faE . ?faE rdfs:label ?father . FILTER(LANG(?father) = "en") }}
  OPTIONAL {{ ?item wdt:P25 ?moE . ?moE rdfs:label ?mother . FILTER(LANG(?mother) = "en") }}
  OPTIONAL {{ ?item wdt:P40 ?chE . ?chE rdfs:label ?child . FILTER(LANG(?child) = "en") }}
}}
GROUP BY ?item ?itemLabel ?enwiki
"""

#: Wikidata property -> kinship role, in the lake's vocabulary.
FAMILY_FIELDS = (
    ("spouses", "spouse"),
    ("fathers", "father"),
    ("mothers", "mother"),
    ("children", "child"),
)


@dataclass
class WikidataPerson:
    qid: str
    name: str
    enwiki: str | None = None
    birth_date: str | None = None
    death_date: str | None = None
    birth_place: str | None = None
    death_place: str | None = None
    residence: str | None = None
    occupations: list[str] = field(default_factory=list)
    employers: list[str] = field(default_factory=list)
    spouses: list[str] = field(default_factory=list)
    fathers: list[str] = field(default_factory=list)
    mothers: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)

    @property
    def wikidata_url(self) -> str:
        return f"https://www.wikidata.org/wiki/{self.qid}"

    @property
    def wikipedia_url(self) -> str | None:
        if not self.enwiki:
            return None
        from urllib.parse import quote

        return "https://en.wikipedia.org/wiki/" + quote(
            self.enwiki.replace(" ", "_"), safe=":_()%,.-"
        )


def _value(binding: dict, key: str) -> str | None:
    raw = (binding.get(key) or {}).get("value")
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _clean_label(text: str | None) -> str | None:
    """A label, or None when WDQS handed back an entity id instead."""
    if not text:
        return None
    text = text.strip()
    if not text or _QID_RE.match(text):
        return None
    return text


def _labels(binding: dict, key: str) -> list[str]:
    """Split an aggregated field, dropping ids and duplicates, order preserved."""
    raw = _value(binding, key)
    if not raw:
        return []
    out: list[str] = []
    for part in raw.split(SEP):
        label = _clean_label(part)
        if label and label not in out:
            out.append(label)
    return out


def _date(binding: dict, key: str) -> str | None:
    """Wikidata returns 1945-12-30T00:00:00Z; the lake stores calendar dates."""
    raw = _value(binding, key)
    if not raw:
        return None
    text = raw.split("T", 1)[0]
    return text if re.match(r"^-?\d{4}-\d{2}-\d{2}$", text) else None


def _qid(binding: dict) -> str | None:
    uri = _value(binding, "item")
    if not uri:
        return None
    tail = uri.rstrip("/").rsplit("/", 1)[-1]
    return tail if _QID_RE.match(tail) else None


def parse_bindings(bindings: list[dict]) -> list[WikidataPerson]:
    """SPARQL rows -> people. Never raises; unusable rows are dropped.

    A row with no item, or whose label is just the entity id, is discarded
    rather than stored — a person named "Q1" is not a fact about anyone.
    """
    seen: dict[str, WikidataPerson] = {}
    for b in bindings or []:
        if not isinstance(b, dict):
            continue
        qid = _qid(b)
        if not qid or qid in seen:
            continue
        name = _clean_label(_value(b, "itemLabel"))
        if not name:
            continue
        seen[qid] = WikidataPerson(
            qid=qid,
            name=name,
            enwiki=_value(b, "enwiki"),
            birth_date=_date(b, "birth_date"),
            death_date=_date(b, "death_date"),
            birth_place=_clean_label(_value(b, "birth_place")),
            death_place=_clean_label(_value(b, "death_place")),
            residence=_clean_label(_value(b, "residence")),
            occupations=_labels(b, "occupations"),
            employers=_labels(b, "employers"),
            spouses=_labels(b, "spouses"),
            fathers=_labels(b, "fathers"),
            mothers=_labels(b, "mothers"),
            children=_labels(b, "children"),
        )
    return list(seen.values())


def to_parse_dict(person: WikidataPerson) -> dict:
    """Shape a person for `PeopleLake.upsert_person_from_parse`.

    Relatives go in `relatives`, not `survivors` or `preceded`. Those two
    buckets hard-code `living=1` and `living=0`; Wikidata states that a spouse
    or a child *exists*, and says nothing about whether they are alive. Putting
    them in either bucket would assert a fact no source supports, so the third
    bucket records `living` as NULL.

    Fields Wikidata does not carry — funeral home, cemetery, service info — are
    left absent rather than blank, so a later prose pass can fill them without
    having to distinguish "" from "not looked at".
    """
    relatives = []
    for attr, role in FAMILY_FIELDS:
        for name in getattr(person, attr, []) or []:
            relatives.append({
                "name": name,
                "role": role,
                "evidence_span": f"wikidata:{person.qid} {role}",
            })

    return {
        "decedent_name": person.name,
        "birth_date": person.birth_date,
        "death_date": person.death_date,
        "birth_place": person.birth_place,
        "death_place": person.death_place,
        "residence": person.residence,
        # Joined for the single free-text column the lake keeps. The list is
        # preserved in props by the caller if it ever needs the parts back.
        "occupation": ", ".join(person.occupations) or None,
        "employers": person.employers,
        "relatives": relatives,
        "aka": [],
        # Explicitly None: Wikidata has no funeral home or cemetery for
        # essentially anyone, and "" would read as checked-and-empty.
        "funeral_home": None,
        "cemetery": None,
        "age": None,
        "military": None,
    }


# --- harvest ---------------------------------------------------------------

UA = "UmbraOSINT/0.2 (https://umbra-osint.com; security@umbra-osint.com)"

#: Newest first. WDQS is happier with several bounded windows than one huge
#: range, and recent decades are the ones an investigator is most likely to
#: ask about.
YEAR_WINDOWS = (
    (2020, 2027), (2015, 2020), (2010, 2015), (2000, 2010),
    (1990, 2000), (1980, 1990), (1970, 1980), (1900, 1970),
)

SOURCE_HOST = "wikidata.org"


def _cursor_key(y0: int, y1: int) -> str:
    return f"wikidata_offset:{y0}-{y1}"


def harvest_claims(
    *,
    add: int = 400,
    settings=None,
    http=None,
    windows=None,
    confidence: float = 0.9,
    pause_s: float = 1.0,
    reset: bool = False,
    page_size: int = 1000,
) -> dict:
    """Fetch structured claims and write them into the people lake.

    Pages with a persisted per-window cursor. The first version had a LIMIT and
    no OFFSET over fixed year windows, so eight windows times a 2,000 cap was a
    hard ceiling of 16,000 rows — and every re-run fetched the *same* 16,000,
    which meant the lake could never reach the 454,614 the source holds.

    `pause_s` is a courtesy to WDQS, which is a free shared service that
    rate-limits hard. The first version had no delay at all.

    Counts `new` and `updated` separately. The first version reported `written`,
    which counted upserts — so a run that re-wrote the same people and added
    nobody looked exactly like one that added them.
    """
    from umbra.core.config import get_settings
    from umbra.core.http_guard import GuardedClient
    from umbra.lake.people import PeopleLake
    from umbra.people.names import canonical

    settings = settings or get_settings()
    windows = windows or YEAR_WINDOWS
    page_size = max(1, min(2000, int(page_size)))

    own_http = http is None
    if own_http:
        http = GuardedClient(
            timeout=90.0,
            headers={"User-Agent": UA, "Accept": "application/sparql-results+json"},
        )

    lake = PeopleLake.from_settings(settings)
    new = updated = 0
    errors: list[str] = []
    exhausted: list[str] = []
    try:
        def _get_cursor(key: str) -> int:
            if reset:
                return 0
            row = lake._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            try:
                return int(row[0]) if row else 0
            except (TypeError, ValueError):
                return 0

        def _set_cursor(key: str, value: int) -> None:
            _set_flag(key, str(value))

        def _set_flag(key: str, value: str) -> None:
            lake._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            lake._conn.commit()

        for y0, y1 in windows:
            if new + updated >= add:
                break
            key = _cursor_key(y0, y1)
            offset = _get_cursor(key)

            while new + updated < add:
                query = PERSON_QUERY.format(
                    year_from=y0, year_to=y1, limit=page_size, offset=offset
                )
                try:
                    resp = http.get(SPARQL_ENDPOINT,
                                    params={"query": query, "format": "json"})
                    if getattr(resp, "status_code", 200) >= 400:
                        errors.append(f"{y0}-{y1}@{offset}: HTTP {resp.status_code}")
                        break
                    bindings = (resp.json().get("results") or {}).get("bindings") or []
                except Exception as exc:  # noqa: BLE001
                    # A failed page is skipped, not fatal: a partial corpus from
                    # the windows that answered beats nothing from all of them.
                    errors.append(f"{y0}-{y1}@{offset}: {exc}")
                    break

                if not bindings:
                    # The window is exhausted. Asking again forever is how a
                    # nightly job burns a free service's quota for nothing.
                    exhausted.append(f"{y0}-{y1}")
                    _set_flag(f"wikidata_exhausted:{y0}-{y1}", "1")
                    break

                _set_flag(f"wikidata_exhausted:{y0}-{y1}", "0")

                for person in parse_bindings(bindings):
                    if new + updated >= add:
                        break
                    existed = lake._conn.execute(
                        "SELECT 1 FROM people WHERE norm_name = ?",
                        (canonical(person.name),),
                    ).fetchone()
                    try:
                        lake.upsert_person_from_parse(
                            decedent_name=person.name,
                            parse=to_parse_dict(person),
                            source_url=person.wikidata_url,
                            title=person.name,
                            source_host=SOURCE_HOST,
                            http_status=200,
                            confidence=confidence,
                        )
                        if existed:
                            updated += 1
                        else:
                            new += 1
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{person.qid}: {exc}")

                offset += len(bindings)
                _set_cursor(key, offset)
                if pause_s:
                    time.sleep(pause_s)

        # Last-run counts, so `people status` shows whether the nightly job is
        # advancing without waiting on the next run's output.
        _set_flag("wikidata_claims_last_new", str(new))
        _set_flag("wikidata_claims_last_updated", str(updated))
        _set_flag("wikidata_claims_last_at", datetime.now(timezone.utc).isoformat())

        status = lake.status()
    finally:
        lake.close()
        if own_http:
            http.close()

    return {
        "new": new,
        "updated": updated,
        "windows": len(windows),
        "exhausted": exhausted,
        "errors": errors[:10],
        "error_count": len(errors),
        "people": status.people,
        "kinship_edges": status.kinship_edges,
    }
