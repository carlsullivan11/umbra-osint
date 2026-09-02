"""Pre-UI readiness: people lake must be seeded and queryable.

This asserts a property of the **operator's data**, not of the code — whether
`umbra people seed` has been run against the default data dir. That distinction
matters because the deploy gate runs pytest inside a clean image whose data dir
is an empty `/tmp/umbra-test-data`, where "the lake is seeded" is false by
construction and can never become true.

It did exactly that. Between 2026-08-20 and 2026-08-30 this test failed on the
build box every time, `run_tests()` raised, and **thirteen commits never
reached production** — the poll-deploy timer retried every two minutes for nine
days, pulling the new code, failing the gate, and rolling nothing out. From the
outside the site simply looked like it had stopped receiving updates.

So it skips when there is no lake, rather than failing. A readiness gate that
blocks the pipeline it is supposed to protect is not a gate, it is an outage —
and pytest reports skips, so the check stays visible rather than silently green.
Lake freshness belongs in `umbra doctor`, where an operator looks on purpose.
"""

from __future__ import annotations

import pytest

from umbra.core.config import get_settings
from umbra.lake.people import PeopleLake
from umbra.people.seed import DEFAULT_SEEDS


def test_default_people_lake_is_seeded_and_queryable():
    """Gate before website person-search UI.

    Requires `umbra people seed` against the default data dir at least once.
    Skipped where no lake exists (CI, the deploy test image, a fresh clone).
    """
    lake = PeopleLake.from_settings(get_settings())
    try:
        st = lake.status()
        if not st.synced:
            pytest.skip(
                "people lake not seeded in this environment "
                f"({st.path}) — run `umbra people seed`. Skipped rather than "
                "failed: this checks operator data, and failing it here blocks "
                "every deploy."
            )
        assert st.people >= 10, f"need ≥10 people, have {st.people}"
        assert st.obituaries >= st.people, st
        assert st.kinship_edges >= 1, "expected some kinship from wiki family text"

        missing = []
        for sp in DEFAULT_SEEDS[:25]:
            hits = lake.lookup_name(sp.name, limit=1)
            if not hits:
                missing.append(sp.name)
                continue
            obits = lake.obituaries_for_person(hits[0]["id"])
            assert obits, f"no obit links for {sp.name}"
            assert all(o.get("url", "").startswith("http") for o in obits)

        assert not missing, f"seed names missing from lake: {missing}"

        # partial search
        assert lake.lookup_name("Franklin")
        assert lake.lookup_name("Jobs")
    finally:
        lake.close()
