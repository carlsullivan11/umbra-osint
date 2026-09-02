"""SQLite must end up matching the models, without a hand-written migration.

Found during the feature review. `umbra phone check` died with:

    OperationalError: no such column: phone_numbers.active

The listing lifecycle (active / delisted_at / report source) shipped one deploy
after the phone tables. The migration was written into `_migrate_postgres` and
never mirrored into `_migrate_sqlite` — so production, on Postgres, was fine,
while **every SQLite install broke**. SQLite is what every `pip install
umbra-osint` uses, so the audience that broke was the whole OSS CLI one, and the
web UI kept working the entire time, which is why nobody noticed.

Hand-maintaining a per-column list is how that happens. `_sqlite_reconcile`
diffs the model against the database instead, so a newly added column needs no
migration written at all — and this file is the guard on that.
"""
from __future__ import annotations

import warnings

import pytest
from sqlalchemy import create_engine, inspect, text

warnings.filterwarnings("ignore")

from umbra.db.schema import (  # noqa: E402
    Base,
    _migrate_sqlite,
    _sqlite_reconcile,
    sqlite_structural_drift,
)


@pytest.fixture
def engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path}/t.sqlite")


def _legacy_phone_tables(engine) -> None:
    """The phone tables exactly as they shipped before the lifecycle columns."""
    with engine.begin() as c:
        c.execute(text("""
            CREATE TABLE phone_numbers (
              id VARCHAR(32) PRIMARY KEY,
              e164 VARCHAR(24),
              report_count INTEGER DEFAULT 0,
              agree_count INTEGER DEFAULT 0,
              disagree_count INTEGER DEFAULT 0,
              first_report_at TIMESTAMP,
              last_report_at TIMESTAMP,
              hidden BOOLEAN DEFAULT 0,
              created_at TIMESTAMP,
              updated_at TIMESTAMP
            )"""))
        c.execute(text("""
            CREATE TABLE phone_reports (
              id VARCHAR(32) PRIMARY KEY,
              phone_id VARCHAR(32),
              reporter_key VARCHAR(64),
              category VARCHAR(32),
              note TEXT,
              frequency VARCHAR(32),
              retracted BOOLEAN DEFAULT 0,
              hidden BOOLEAN DEFAULT 0,
              created_at TIMESTAMP,
              updated_at TIMESTAMP
            )"""))


def test_the_exact_bug_that_broke_umbra_phone_check(engine):
    _legacy_phone_tables(engine)
    _migrate_sqlite(engine)

    cols = {c["name"] for c in inspect(engine).get_columns("phone_numbers")}
    assert "active" in cols
    assert "delisted_at" in cols
    report_cols = {c["name"] for c in inspect(engine).get_columns("phone_reports")}
    assert "source" in report_cols


def test_no_model_column_is_left_missing_anywhere(engine):
    """The general guarantee, across every table Umbra defines.

    Create the whole schema, drop a column out of each table that can spare one,
    then reconcile and demand the model and the database agree again.
    """
    Base.metadata.create_all(engine)

    dropped: list[str] = []
    with engine.begin() as c:
        for name, table in Base.metadata.tables.items():
            pk = {col.name for col in table.primary_key.columns}
            # SQLite refuses to DROP an indexed column ("error in index … after
            # drop column"), so those cannot take part in this simulation.
            indexed = {c.name for idx in table.indexes for c in idx.columns}
            # …and refuses to drop a column named in a foreign key.
            fk = {c.name for c in table.columns if c.foreign_keys}
            spare = [
                col for col in table.columns
                if col.name not in pk
                and col.name not in indexed
                and col.name not in fk
                and not col.index
                and col.nullable
                and not col.unique
            ]
            if not spare:
                continue
            col = spare[-1]
            c.execute(text(f"ALTER TABLE {name} DROP COLUMN {col.name}"))
            dropped.append(f"{name}.{col.name}")

    assert dropped, "nothing was dropped — the test would prove nothing"

    with engine.begin() as c:
        added = _sqlite_reconcile(c)

    insp = inspect(engine)
    still_missing = []
    for name, table in Base.metadata.tables.items():
        live = {col["name"] for col in insp.get_columns(name)}
        still_missing += [f"{name}.{c.name}" for c in table.columns if c.name not in live]

    assert not still_missing, f"reconcile left columns missing: {still_missing}"
    assert set(added) == set(dropped)


def test_reconcile_is_idempotent(engine):
    Base.metadata.create_all(engine)
    with engine.begin() as c:
        assert _sqlite_reconcile(c) == []
    with engine.begin() as c:
        assert _sqlite_reconcile(c) == []


def test_a_changed_primary_key_is_reported_not_guessed_at(engine):
    """SQLite cannot ALTER a primary key. That must be surfaced, not papered
    over — and never by dropping a table that holds someone's data."""
    with engine.begin() as c:
        c.execute(text("CREATE TABLE ftc_complaints (seq INTEGER PRIMARY KEY, e164 VARCHAR(24))"))

    with engine.begin() as c:
        drift = sqlite_structural_drift(c)

    assert "ftc_complaints" in drift
    assert "id" in drift["ftc_complaints"]


def test_a_table_with_rows_is_never_dropped(engine):
    """The rebuild path is only safe because it refuses to run on real data."""
    with engine.begin() as c:
        c.execute(text("CREATE TABLE ftc_complaints (seq INTEGER PRIMARY KEY, e164 VARCHAR(24))"))
        c.execute(text("INSERT INTO ftc_complaints (seq, e164) VALUES (1, '+15555550100')"))

    _migrate_sqlite(engine)

    with engine.begin() as c:
        kept = c.execute(text("SELECT COUNT(*) FROM ftc_complaints")).scalar()
    assert kept == 1, "a migration must not destroy collected rows to fit the model"


def test_an_empty_drifted_table_is_rebuilt(engine):
    with engine.begin() as c:
        c.execute(text("CREATE TABLE ftc_complaints (seq INTEGER PRIMARY KEY, e164 VARCHAR(24))"))

    _migrate_sqlite(engine)

    # Dropped, so the next create_all can build it correctly.
    assert not inspect(engine).has_table("ftc_complaints")


def test_a_real_upgrade_through_the_installed_cli(tmp_path):
    """End to end, the way a pip user hits it.

    The tests above call `_migrate_sqlite` directly. That is not the same thing
    as proving the command works — when I first reproduced this by hand I
    invoked `python -m umbra.cli.main`, which has no __main__ guard, so it
    imported the module, exited 0, migrated nothing, and looked like the fix had
    failed. The harness was wrong, not the fix, and only running the real
    console script showed it.

    So this drives the actual entry point against a database built from the
    pre-fix schema, and demands the user's existing rows survive.
    """
    import os
    import shutil
    import sqlite3
    import subprocess

    umbra_bin = shutil.which("umbra")
    if not umbra_bin:
        pytest.skip("umbra console script not on PATH (not an editable install)")

    db = tmp_path / "umbra.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE phone_numbers (
          id VARCHAR(32) PRIMARY KEY, e164 VARCHAR(24) UNIQUE,
          report_count INTEGER DEFAULT 0, agree_count INTEGER DEFAULT 0,
          disagree_count INTEGER DEFAULT 0, first_report_at TIMESTAMP,
          last_report_at TIMESTAMP, hidden BOOLEAN DEFAULT 0,
          created_at TIMESTAMP, updated_at TIMESTAMP);
        CREATE TABLE phone_reports (
          id VARCHAR(32) PRIMARY KEY, phone_id VARCHAR(32), reporter_key VARCHAR(64),
          category VARCHAR(32), note TEXT, frequency VARCHAR(32),
          retracted BOOLEAN DEFAULT 0, hidden BOOLEAN DEFAULT 0,
          created_at TIMESTAMP, updated_at TIMESTAMP);
        INSERT INTO phone_numbers (id,e164,report_count,agree_count,hidden,created_at,updated_at)
        VALUES ('p_legacy01','+18005551212',3,2,0,'2026-01-01','2026-01-01');
        INSERT INTO phone_reports (id,phone_id,reporter_key,category,note,retracted,hidden,created_at,updated_at)
        VALUES ('r_legacy01','p_legacy01','k1','scam','synthetic',0,0,'2026-01-01','2026-01-01');
    """)
    con.commit()
    con.close()

    env = {**os.environ, "UMBRA_DATA_DIR": str(tmp_path)}
    proc = subprocess.run([umbra_bin, "phone", "check", "+1 800 555 1212"],
                          capture_output=True, text=True, env=env, timeout=300)
    output = (proc.stdout or "") + (proc.stderr or "")

    assert "no such column" not in output, output[:600]
    assert "Traceback" not in output, output[:600]
    assert proc.returncode == 0, output[:600]

    con = sqlite3.connect(db)
    try:
        cols = {r[1] for r in con.execute("PRAGMA table_info(phone_numbers)")}
        assert {"active", "delisted_at"} <= cols
        row = con.execute(
            "SELECT report_count, agree_count, active FROM phone_numbers WHERE id='p_legacy01'"
        ).fetchone()
        # The upgrade must not touch the user's counts, and an existing listing
        # stays active rather than silently delisting itself.
        assert row == (3, 2, 1)
        assert con.execute("SELECT COUNT(*) FROM phone_reports").fetchone()[0] == 1
    finally:
        con.close()
