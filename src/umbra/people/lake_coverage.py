"""Lake emptiness/import status for `/people/coverage`.

This is a coverage question, not an identity question: an empty lake means
"not imported", never "not a clinician" or "not an officer" or "not a
licensee". A miss here is a fact about Umbra's own corpus, not a claim about
the person being searched.

Every lake here is a local SQLite file opened read/create-only — nothing here
makes a network call, so this is safe to call from a request handler and
safe to exercise with fixture files in tests.
"""

from __future__ import annotations

import importlib
from typing import Any

# (label, module, class name, key in status() holding the row count)
_LAKE_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("FEC", "umbra.lake.fec", "FecLake", "contributors"),
    ("parcels", "umbra.lake.parcels", "ParcelLake", "parcels"),
    ("NPPES", "umbra.lake.nppes", "NppesLake", "providers"),
    ("IRS 990", "umbra.lake.irs990", "Irs990Lake", "officers"),
    ("ULS", "umbra.lake.uls", "UlsLake", "licenses"),
)


def _miss(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "available": False,
        "count": 0,
        "imported_at": None,
        "note": "not imported",
    }


def _people_row() -> dict[str, Any]:
    try:
        from umbra.core.config import get_settings
        from umbra.lake.people import PeopleLake

        lake = PeopleLake.from_settings(get_settings())
        try:
            st = lake.status()
        finally:
            lake.close()
        count = int(st.people or 0)
        return {
            "name": "people",
            "available": count > 0,
            "count": count,
            "imported_at": st.last_upsert,
            "note": None if count > 0 else "not imported",
        }
    except Exception:  # noqa: BLE001 - a broken/missing lake is a miss, not a 500
        return _miss("people")


def _inmate_facts_row() -> dict[str, Any]:
    """`inmate_facts` lives as a table inside the people lake (same shape as
    `sor_sources`/`sor_facts`), not a standalone lake file — see
    `umbra.lake.people`. A miss here is coverage, not identity: an empty
    table reads "not imported", never "not an inmate".
    """
    try:
        from umbra.core.config import get_settings
        from umbra.lake.people import PeopleLake

        lake = PeopleLake.from_settings(get_settings())
        try:
            with lake._lock:
                count = lake._conn.execute(
                    "SELECT COUNT(*) FROM inmate_facts"
                ).fetchone()[0]
                row = lake._conn.execute(
                    "SELECT MAX(fetched_at) FROM inmate_facts"
                ).fetchone()
        finally:
            lake.close()
        count = int(count or 0)
        imported_at = row[0] if row else None
        return {
            "name": "inmate_facts",
            "available": count > 0,
            "count": count,
            "imported_at": imported_at,
            "note": None if count > 0 else "not imported",
        }
    except Exception:  # noqa: BLE001 - a broken/missing lake is a miss, not a 500
        return _miss("inmate_facts")


def _lake_row(name: str, module_name: str, cls_name: str, count_key: str) -> dict[str, Any]:
    try:
        module = importlib.import_module(module_name)
        cls = getattr(module, cls_name)
        lake = cls()
        try:
            st = lake.status()
        finally:
            lake.close()
        count = int(st.get(count_key) or 0)
        return {
            "name": name,
            "available": count > 0,
            "count": count,
            "imported_at": st.get("imported_at"),
            "note": None if count > 0 else "not imported",
        }
    except Exception:  # noqa: BLE001 - a broken/missing lake is a miss, not a 500
        return _miss(name)


def lakes_coverage_payload() -> dict[str, Any]:
    """Row counts / last import per owned lake: people, FEC, parcels, NPPES,
    IRS 990, ULS, inmate_facts. Never raises — a lake that cannot be opened
    reports as "not imported" rather than failing the page.
    """
    lakes = [_people_row()]
    for name, module_name, cls_name, count_key in _LAKE_SPECS:
        lakes.append(_lake_row(name, module_name, cls_name, count_key))
    lakes.append(_inmate_facts_row())
    return {"lakes": lakes}
