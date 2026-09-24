"""Turn obituary parse / people-lake rows into case-graph entities + edges.

The people lake is the durable corpus. The case graph is a *view* of one
investigation. Both surfaces must emit the same entity types:

- PERSON (decedent facts + kinship candidates)
- LOCATION (residence, birth, death, cemetery)
- ORG (funeral home, military unit/branch when named)
- URL (obituary / memorial source) — callers usually add these themselves

Kinship stays ``related_to`` with ``manual_confirm`` until ``umbra people confirm``.
"""

from __future__ import annotations

from typing import Any, Iterable

from umbra.core.models import EdgeIn, EdgeType, EntityIn, EntityType
from umbra.core.normalize import entity_key


_PLACE_FIELDS: tuple[tuple[str, str], ...] = (
    ("residence", "residence"),
    ("birth_place", "birth"),
    ("death_place", "death"),
    ("cemetery", "cemetery"),
)


def _src_key(name: str) -> str:
    return entity_key(EntityType.PERSON, name)


def _place_ok(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 3:
        return False
    # Drop parser junk
    if v.lower() in {"unknown", "n/a", "none", "the", "and"}:
        return False
    return True


def decedent_entity(
    name: str,
    fields: dict[str, Any],
    *,
    confidence: float = 0.75,
    extra_props: dict[str, Any] | None = None,
) -> EntityIn:
    props: dict[str, Any] = {"source": "obituary_person_graph"}
    for k in (
        "age",
        "birth_date",
        "death_date",
        "birth_place",
        "death_place",
        "residence",
        "occupation",
        "funeral_home",
        "cemetery",
        "military",
    ):
        if fields.get(k) not in (None, "", []):
            props[k] = fields[k]
    aka = fields.get("aka") or []
    if aka:
        props["aka"] = aka[:8]
    if extra_props:
        props.update(extra_props)
    return EntityIn(
        type=EntityType.PERSON,
        value=name,
        display_name=name,
        confidence=confidence,
        props=props,
    )


def graph_from_parse(
    decedent_name: str,
    parse: dict[str, Any],
    *,
    source_url: str | None = None,
    source: str = "obituary",
    src_key: str | None = None,
) -> tuple[list[EntityIn], list[EdgeIn]]:
    """Entities/edges for one notice parse (survivors + places + orgs)."""
    name = (decedent_name or parse.get("decedent_name") or "").strip()
    if not name:
        return [], []
    src = src_key or _src_key(name)
    entities: list[EntityIn] = [decedent_entity(name, parse)]
    edges: list[EdgeIn] = []

    def add_kin(person: dict[str, Any], *, living: bool) -> None:
        rname = (person.get("name") or "").strip()
        if not rname or rname.lower() == name.lower():
            return
        role = person.get("role") or "unknown"
        conf = 0.5 if role != "unknown" else 0.4
        entities.append(
            EntityIn(
                type=EntityType.PERSON,
                value=rname,
                display_name=rname,
                confidence=conf,
                props={
                    "source": f"{source}_survivor" if living else f"{source}_preceded",
                    "kinship_role": role,
                    "related_to": name,
                    "living": living,
                    "manual_confirm": True,
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.PERSON, rname),
                rel=EdgeType.RELATED_TO,
                confidence=conf,
                props={
                    "kinship_role": role,
                    "direction": "decedent_to_relative",
                    "source": source,
                    "living": living,
                    "manual_confirm": True,
                    "source_url": source_url,
                    "evidence_span": (person.get("evidence_span") or "")[:200],
                },
            )
        )

    for s in parse.get("survivors") or []:
        if isinstance(s, dict):
            add_kin(s, living=bool(s.get("living", True)))
    for s in parse.get("preceded") or []:
        if isinstance(s, dict):
            rec = dict(s)
            rec["living"] = False
            add_kin(rec, living=False)

    for field, kind in _PLACE_FIELDS:
        val = parse.get(field)
        if not _place_ok(str(val) if val else ""):
            continue
        place = str(val).strip()
        entities.append(
            EntityIn(
                type=EntityType.LOCATION,
                value=place,
                confidence=0.55,
                props={"kind": kind, "related_to": name, "source": source},
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.LOCATION, place),
                rel=EdgeType.LOCATED_IN,
                confidence=0.55,
                props={"kind": kind, "source": source, "source_url": source_url},
            )
        )

    fh = (parse.get("funeral_home") or "").strip()
    if _place_ok(fh):
        entities.append(
            EntityIn(
                type=EntityType.ORG,
                value=fh,
                confidence=0.5,
                props={"kind": "funeral_home", "related_to": name, "source": source},
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.ORG, fh),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.5,
                props={"kind": "funeral_home", "source": source, "source_url": source_url},
            )
        )

    mil = (parse.get("military") or "").strip()
    if _place_ok(mil):
        entities.append(
            EntityIn(
                type=EntityType.ORG,
                value=mil,
                confidence=0.45,
                props={"kind": "military", "related_to": name, "source": source},
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.ORG, mil),
                rel=EdgeType.MEMBER_OF,
                confidence=0.45,
                props={"kind": "military", "source": source, "source_url": source_url},
            )
        )

    occ = (parse.get("occupation") or "").strip()
    if occ and _place_ok(occ) and any(
        tok in occ.lower() for tok in ("inc", "llc", "corp", "company", "university", "hospital")
    ):
        entities.append(
            EntityIn(
                type=EntityType.ORG,
                value=occ,
                confidence=0.4,
                props={"kind": "employer_guess", "related_to": name, "source": source},
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.ORG, occ),
                rel=EdgeType.WORKS_AT,
                confidence=0.4,
                props={"kind": "occupation", "source": source, "manual_confirm": True},
            )
        )

    for alias in parse.get("aka") or []:
        alias_s = str(alias).strip()
        if not _place_ok(alias_s) or alias_s.lower() == name.lower():
            continue
        entities.append(
            EntityIn(
                type=EntityType.PERSON,
                value=alias_s,
                display_name=alias_s,
                confidence=0.55,
                props={"kind": "aka", "related_to": name, "source": source},
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.PERSON, alias_s),
                rel=EdgeType.SAME_AS,
                confidence=0.55,
                props={"kind": "aka", "source": source, "manual_confirm": True},
            )
        )

    return entities, edges


def graph_from_lake(
    decedent_name: str,
    row: dict[str, Any],
    obituaries: Iterable[dict[str, Any]] = (),
    kinship: Iterable[dict[str, Any]] = (),
    *,
    src_key: str | None = None,
    county: Iterable[dict[str, Any]] = (),
    land: Iterable[dict[str, Any]] = (),
    corps: Iterable[dict[str, Any]] = (),
    cameras: Iterable[dict[str, Any]] = (),
    sor: Iterable[dict[str, Any]] = (),
    #: FEC contributors, accepted so `**enrichment_from_lakes(...)` stays a
    #: valid call, and deliberately *not* turned into graph nodes.
    #:
    #: The obvious move would be an ORG node for the employer with an edge from
    #: the person. That would assert employment on the strength of a name
    #: appearing in a filing — the same name in the same ZIP is one row here
    #: whether it is one person or three. The contributions are rendered as
    #: their own list on the page instead, where the caller can label them.
    fec: Iterable[dict[str, Any]] = (),
) -> tuple[list[EntityIn], list[EdgeIn]]:
    """Hydrate a case graph from people-lake rows (offline, no scrape)."""
    parse = {
        "decedent_name": row.get("full_name") or decedent_name,
        "age": row.get("age"),
        "birth_date": row.get("birth_date"),
        "death_date": row.get("death_date"),
        "birth_place": row.get("birth_place"),
        "death_place": row.get("death_place"),
        "residence": row.get("residence"),
        "occupation": row.get("occupation"),
        "funeral_home": row.get("funeral_home"),
        "cemetery": row.get("cemetery"),
        "military": row.get("military"),
        "survivors": [],
        "preceded": [],
    }
    aka = row.get("aka")
    if aka is None:
        raw_aka = row.get("aka_json")
        if isinstance(raw_aka, str) and raw_aka.strip():
            try:
                import json as _json

                aka = _json.loads(raw_aka)
            except Exception:
                aka = []
        elif isinstance(raw_aka, list):
            aka = raw_aka
    if aka:
        parse["aka"] = aka
    for k in kinship:
        rec = {
            "name": k.get("relative_name"),
            "role": k.get("role") or "unknown",
            "evidence_span": k.get("evidence_span") or "",
            "living": bool(k.get("living", 1)),
        }
        confirmed = (k.get("confirmation") or "unknown").lower()
        rec["_confirmation"] = confirmed
        if rec["living"]:
            parse["survivors"].append(rec)
        else:
            parse["preceded"].append(rec)

    ents, edges = graph_from_parse(
        decedent_name,
        parse,
        source="people_lake",
        src_key=src_key,
    )
    # Stamp confirmation from lake onto related_to edges
    conf_by_name = {
        (k.get("relative_name") or "").strip().lower(): (k.get("confirmation") or "unknown")
        for k in kinship
    }
    for e in edges:
        if e.rel != EdgeType.RELATED_TO:
            continue
        # target key is person:<norm>
        for raw, verdict in conf_by_name.items():
            if not raw:
                continue
            if entity_key(EntityType.PERSON, raw) == e.target_key:
                e.props["confirmation"] = verdict
                if verdict == "true":
                    e.props["manual_confirm"] = False
                    e.confidence = max(e.confidence, 0.75)
                elif verdict == "false":
                    e.confidence = 0.15
                    e.props["rejected"] = True

    src = src_key or _src_key(decedent_name)
    for o in obituaries:
        url = o.get("url")
        if not url:
            continue
        ents.append(
            EntityIn(
                type=EntityType.URL,
                value=url,
                display_name=o.get("title") or url,
                confidence=0.8,
                props={
                    "obituary_candidate": True,
                    "from_people_lake": True,
                    "manual_confirm": True,
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.URL, url),
                rel=EdgeType.MENTIONS,
                confidence=0.8,
                props={"kind": "people_lake_obit", "link": url},
            )
        )
    return attach_record_entities(
        src,
        ents,
        edges,
        county=county,
        land=land,
        corps=corps,
        cameras=cameras,
        sor=sor,
    )


def enrichment_from_lakes(people_lake, name: str, row: dict[str, Any] | None = None, settings=None) -> dict[str, Any]:
    """Pull county/land/corp/SOR + RF cameras (region string *or* geocode radius)."""
    row = row or {}
    q = name or row.get("full_name") or ""
    land = people_lake.land_for_name(q, limit=5) if q else []
    sor = people_lake.sor_for_name(q, limit=8) if q else []
    places: list[str] = []
    for key in ("residence", "death_place", "birth_place"):
        v = (row.get(key) or "").strip()
        if v:
            places.append(v)
    for rec in land:
        s = (rec.get("situs") or "").strip()
        if s:
            places.append(s)
    for rec in sor:
        s = (rec.get("address") or "").strip()
        if s:
            places.append(s)
    cameras: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        from umbra.lake.rf import RfLake

        rf = RfLake.from_settings(settings) if settings is not None else RfLake()
        try:
            rf.backfill_geocode_from_cameras()
        except Exception:
            pass
        for place in places:
            for cam in rf.cameras_for_region(str(place), limit=8):
                cid = str(cam.get("id") or cam.get("osm_id") or cam.get("label"))
                if cid in seen:
                    continue
                seen.add(cid)
                cameras.append(cam)
            coords = rf.geocode_get(place)
            if coords:
                for cam in rf.cameras_near(coords[0], coords[1], km=6.0, limit=8):
                    cid = str(cam.get("id") or cam.get("osm_id") or cam.get("label"))
                    if cid in seen:
                        continue
                    seen.add(cid)
                    cameras.append(cam)
        rf.close()
    except Exception:
        cameras = cameras[:8]
    cameras = cameras[:8]
    # FEC contributors. A separate lake and a separate list on purpose: a name
    # in a campaign finance filing is a name that appears in a filing, not
    # another confirmed fact about the person on screen. Optional and ~4 GB, so
    # its absence must never break a person search.
    fec: list[dict[str, Any]] = []
    if q:
        try:
            from umbra.lake.fec import FecLake

            fec_lake = FecLake()
            try:
                fec = fec_lake.lookup(q, limit=5)
            finally:
                fec_lake.close()
        except Exception:  # noqa: BLE001 - an absent or broken lake is not an outage
            fec = []

    return {
        "county": people_lake.county_for_name(q, limit=8) if q else [],
        "land": land,
        "corps": people_lake.corps_for_name(q, limit=5) if q else [],
        "cameras": cameras,
        "sor": sor,
        "fec": fec,
    }


def attach_record_entities(
    src: str,
    entities: list[EntityIn],
    edges: list[EdgeIn],
    *,
    county: Iterable[dict[str, Any]] = (),
    land: Iterable[dict[str, Any]] = (),
    corps: Iterable[dict[str, Any]] = (),
    cameras: Iterable[dict[str, Any]] = (),
    sor: Iterable[dict[str, Any]] = (),
) -> tuple[list[EntityIn], list[EdgeIn]]:
    """Add county URLs, land/corp candidates, nearby OSM cameras, SOR facts."""
    for row in list(county)[:8]:
        url = row.get("url")
        if not url:
            continue
        entities.append(
            EntityIn(
                type=EntityType.URL,
                value=url,
                display_name=row.get("title") or url,
                confidence=0.5,
                props={
                    "kind": row.get("kind") or "county",
                    "county_record": True,
                    "name_hit": bool(row.get("name_hit")),
                    "region": row.get("region"),
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.URL, url),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.45,
                props={"kind": "county_source", "source": "county_records"},
            )
        )
    for row in list(land)[:5]:
        situs = row.get("situs")
        apn = row.get("apn")
        loc = situs or (f"APN {apn}" if apn else None)
        if not loc:
            continue
        entities.append(
            EntityIn(
                type=EntityType.LOCATION,
                value=loc,
                confidence=0.4,
                props={
                    "kind": "parcel",
                    "apn": apn,
                    "source_url": row.get("source_url"),
                    "manual_confirm": True,
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.LOCATION, loc),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.35,
                props={"kind": "land_candidate", "manual_confirm": True},
            )
        )
    for row in list(corps)[:5]:
        org = (row.get("org_name") or "").strip()
        if not org:
            continue
        entities.append(
            EntityIn(
                type=EntityType.ORG,
                value=org,
                confidence=0.4,
                props={
                    "kind": "sos_candidate",
                    "file_number": row.get("file_number"),
                    "source_url": row.get("source_url"),
                    "manual_confirm": True,
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.ORG, org),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.35,
                props={"kind": "corp_officer_candidate", "manual_confirm": True},
            )
        )
    for row in list(cameras)[:8]:
        label = row.get("label") or "surveillance"
        try:
            lat, lon = float(row["lat"]), float(row["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        place = f"camera {label} ({lat:.5f},{lon:.5f})"
        entities.append(
            EntityIn(
                type=EntityType.LOCATION,
                value=place,
                confidence=0.45,
                props={
                    "kind": "osm_surveillance",
                    "osm_id": row.get("osm_id"),
                    "source": "rf_lake",
                    "deflock_equivalent": True,
                },
            )
        )
        edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.LOCATION, place),
                rel=EdgeType.ASSOCIATED_WITH,
                confidence=0.35,
                props={"kind": "surveillance", "source": "rf_lake"},
            )
        )
    for row in list(sor)[:8]:
        url = row.get("source_url")
        addr = row.get("address")
        if url:
            entities.append(
                EntityIn(
                    type=EntityType.URL,
                    value=url,
                    confidence=0.55,
                    props={"kind": "sex_offender_registry", "manual_confirm": True},
                )
            )
            edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, url),
                    rel=EdgeType.ASSOCIATED_WITH,
                    confidence=0.5,
                    props={"kind": "sor_source", "manual_confirm": True},
                )
            )
        if addr:
            entities.append(
                EntityIn(
                    type=EntityType.LOCATION,
                    value=addr,
                    confidence=0.5,
                    props={"kind": "sor_listed_address", "source_url": url, "manual_confirm": True},
                )
            )
            edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.LOCATION, addr),
                    rel=EdgeType.LOCATED_IN,
                    confidence=0.4,
                    props={"kind": "sor_candidate", "manual_confirm": True},
                )
            )
    return entities, edges


def serialize_graph(entities: list[EntityIn], edges: list[EdgeIn]) -> dict[str, Any]:
    """JSON-ready dump for CLI /v1 (enums as strings)."""
    return {
        "entity_count": len(entities),
        "edge_count": len(edges),
        "by_type": {
            t.value: sum(1 for e in entities if e.type == t)
            for t in (
                EntityType.PERSON,
                EntityType.LOCATION,
                EntityType.ORG,
                EntityType.URL,
            )
            if any(e.type == t for e in entities)
        },
        "entities": [e.model_dump(mode="json") for e in entities],
        "edges": [e.model_dump(mode="json") for e in edges],
    }
