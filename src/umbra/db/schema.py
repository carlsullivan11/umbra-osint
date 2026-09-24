from __future__ import annotations

import logging

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from umbra.core.config import Settings, get_settings
from umbra.core.models import utcnow


class Base(DeclarativeBase):
    pass


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    authorization_basis: Mapped[str] = mapped_column(String(64), nullable=False)
    # Anonymous visitor session id (umbra.web.session). NULL means the case
    # predates ownership or came from the CLI — either way it belongs to the
    # operator, never to whoever asks first.
    owner_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed: Mapped[bool] = mapped_column(Boolean, default=False)

    entities: Mapped[list["Entity"]] = relationship(back_populates="case")
    edges: Mapped[list["Edge"]] = relationship(back_populates="case")
    runs: Mapped[list["Run"]] = relationship(back_populates="case")
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="case")


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    norm_key: Mapped[str] = mapped_column(String(1200), index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    is_seed: Mapped[bool] = mapped_column(Boolean, default=False)
    # unknown | true | false | disputed
    verification: Mapped[str] = mapped_column(String(32), default="unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    merged_into_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)

    case: Mapped[Case] = relationship(back_populates="entities")


class Edge(Base):
    __tablename__ = "edges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    rel: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="edges")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    run_id: Mapped[Optional[str]] = mapped_column(ForeignKey("runs.id"), nullable=True)
    entity_id: Mapped[Optional[str]] = mapped_column(ForeignKey("entities.id"), nullable=True)
    collector: Mapped[str] = mapped_column(String(128))
    source_name: Mapped[str] = mapped_column(String(256))
    source_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    raw_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    raw_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=2)
    max_entities: Mapped[int] = mapped_column(Integer, default=500)
    collectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="running")
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case: Mapped[Case] = relationship(back_populates="runs")


class Job(Base):
    """A durable unit of collector work.

    The queue lives in the database rather than process memory so that an API
    restart cannot lose queued work (Phase B exit criterion). Status flow:

        queued -> running -> ok | failed
                    ^
                    +-- requeue_stale_jobs() rescues rows abandoned by a
                        worker that died mid-job, which would otherwise sit
                        "running" forever.
    """

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    # queued | running | ok | failed
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    collectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    depth: Mapped[int] = mapped_column(Integer, default=1)
    max_entities: Mapped[int] = mapped_column(Integer, default=500)
    seed_value: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    worker_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    case: Mapped[Case] = relationship()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[Optional[str]] = mapped_column(ForeignKey("cases.id"), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    action: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case: Mapped[Optional[Case]] = relationship(back_populates="audit_events")


class OpsEvent(Base):
    """A deduped operational problem (docs/ERROR-REVIEW-CYCLE.md, E1).

    One row per *fingerprint*, not per occurrence: repeats bump `count` and
    `last_seen`. That is what keeps one broken collector from becoming two
    hundred Telegram messages, which in practice means a muted channel and no
    alerting at all.

    Status flow: open -> ack -> planned -> in_progress -> done | wontfix.
    A `done` event that fires again reopens, so a regression cannot hide inside
    a closed row.
    """

    __tablename__ = "ops_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(4), index=True)     # S0..S4
    kind: Mapped[str] = mapped_column(String(64), index=True)        # http_5xx, job_failed…
    source: Mapped[str] = mapped_column(String(32), default="api")   # api|worker|cron|watcher
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    priority: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)  # P0..P3
    # Drafted at triage — by a human or by the Hermes review job. Present here
    # so "has anyone thought about this yet?" is answerable in SQL.
    proposed_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    muted_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class FeedSource(Base):
    """A polled news source (stage S14 / F1).

    Sources live in the database rather than in config so an operator can add or
    mute one without a deploy; `umbra.feeds.ingest.DEFAULT_SOURCES` only seeds
    the starting pack.
    """

    __tablename__ = "feed_sources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32), default="rss")
    url: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    trust: Mapped[float] = mapped_column(Float, default=0.7)
    last_polled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    items: Mapped[list["FeedItem"]] = relationship(back_populates="source")


class FeedItem(Base):
    """One story. `content_hash` is a URL hash and is UNIQUE, so re-polling a
    feed or receiving the same story from two sources stores it once."""

    __tablename__ = "feed_items"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("feed_sources.id"), index=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    url: Mapped[str] = mapped_column(String(2048))
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # F2 fills these; the column exists now so tagging needs no migration.
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    source: Mapped[FeedSource] = relationship(back_populates="items")


class WatchItem(Base):
    """Persistent watchlist for continuous backend monitoring (no UI)."""

    __tablename__ = "watch_items"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[Optional[str]] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    label: Mapped[str] = mapped_column(String(256), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_checked: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    last_diff: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    check_count: Mapped[int] = mapped_column(Integer, default=0)


class PhoneNumber(Base):
    """A phone number someone looked up or reported (community, not a case).

    Deliberately **not** joined to the investigation graph. A case is evidence an
    operator collected under an authorization basis; a report here is a
    stranger's allegation. Mixing them would poison the provenance model the
    rest of the product rests on — so there is no `case_id` on this table by
    design, and a test enforces its absence.

    Rows created by a mere lookup carry no reports and are pruned by
    `umbra.phone.store.purge_unreported`, so this does not quietly become a log
    of every number anyone typed into the box.
    """

    __tablename__ = "phone_numbers"

    # Opaque. A result URL keyed by the number would spread it through
    # referrers, browser history and search indexes, and would let anyone walk
    # the table by counting.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    e164: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    report_count: Mapped[int] = mapped_column(Integer, default=0)
    agree_count: Mapped[int] = mapped_column(Integer, default=0)
    disagree_count: Mapped[int] = mapped_column(Integer, default=0)
    first_report_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_report_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # A listing is a claim about *now*. Numbers get reassigned and abandoned, so
    # one that has gone quiet for the window drops off the active list rather
    # than carrying a live accusation forever. Delisting is not deletion: the
    # reports stay and `delisted_at` records that it was listed once.
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    delisted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PhoneReport(Base):
    """One person's allegation about one number.

    `reporter_key` is an HMAC of the anonymous owner cookie — enough to enforce
    one open report per person and to ban an abuser, and not enough to identify
    anybody. The raw cookie and the IP are never stored here.
    """

    __tablename__ = "phone_reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    phone_id: Mapped[str] = mapped_column(ForeignKey("phone_numbers.id"), index=True)
    reporter_key: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    # "community" or "operator". Seeding a call log and rendering it as
    # community consensus would be inventing a crowd out of one person, so the
    # page can say which it is.
    source: Mapped[str] = mapped_column(String(16), default="community", index=True)
    note: Mapped[Optional[str]] = mapped_column(String(280), nullable=True)
    frequency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    retracted: Mapped[bool] = mapped_column(Boolean, default=False)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("phone_id", "reporter_key", name="uq_phone_report_reporter"),
    )


class PhoneVote(Base):
    """Agreement or disagreement with a number's reports. One per person."""

    __tablename__ = "phone_votes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    phone_id: Mapped[str] = mapped_column(ForeignKey("phone_numbers.id"), index=True)
    voter_key: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[int] = mapped_column(Integer, default=0)  # +1 agree, -1 disagree
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("phone_id", "voter_key", name="uq_phone_vote_voter"),
    )


class FtcComplaint(Base):
    """One consumer complaint to the FTC's Do Not Call programme.

    An owned index of a public feed — independent of Umbra's community, so it
    corroborates rather than echoes.

    Sourced from the FTC's **daily CSV**, not their API. The API cannot be
    filtered by number, ignores `page`, and walks ~19M records from the oldest
    end with `offset` — 384,000 requests to index. The daily file carries ~11,000
    complaints with ~9,900 distinct numbers, needs no key, and is the same data
    properly aligned. Measured, not assumed.

    Nothing here is verified. The FTC says so, and so does the page that renders
    it.
    """

    __tablename__ = "ftc_complaints"

    # A content hash, because the daily CSV carries no row id. Same complaint
    # re-read from an overlapping file lands on the same key, so ingestion is
    # idempotent without the API's `seq`.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_day: Mapped[str] = mapped_column(String(10), index=True)
    e164: Mapped[str] = mapped_column(String(24), index=True)
    complaint_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True)
    subject: Mapped[Optional[str]] = mapped_column(String(160), nullable=True)
    is_robocall: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    area_code: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PhoneModerationEvent(Base):
    """What an operator hid, purged or banned, and why. Survives the content."""

    __tablename__ = "phone_moderation_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    phone_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    report_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PageView(Base):
    """First-party web analytics event (product metrics, not third-party ads)."""

    __tablename__ = "page_views"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    path: Mapped[str] = mapped_column(String(1024), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    status: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    referrer: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    # Privacy: store hashed visitor id, never raw IP in this table by default
    visitor_hash: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    country: Mapped[Optional[str]] = mapped_column(String(8), nullable=True, index=True)
    cf_ray: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    access_email: Mapped[Optional[str]] = mapped_column(String(320), nullable=True, index=True)
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class LakeSnapshot(Base):
    """One reading of one owned lake: how many rows, and how fresh.

    `umbra doctor` already reports both, but only for *now*. That catches a
    lake nobody is syncing and misses the more dangerous failure — a sync that
    ran, returned HTTP 200, and brought back less than it should have. The Tor
    fetch from dan.me.uk did exactly that: 12KB where 2.4MB was expected, every
    per-request check passing. The only signal was the row count against the
    previous day's.

    Kept as an append-only series rather than a mutable "current state" row,
    because the comparison *is* the signal.
    """

    __tablename__ = "lake_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lake: Mapped[str] = mapped_column(String(64), index=True)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    #: When the lake itself last ingested, as distinct from when we looked at
    #: it. Null when the lake cannot say.
    synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)


class SentinelObservation(Base):
    """A request to Umbra that looked like scanning, and the address it came from.

    This is the **one** place Umbra stores a raw client IP, and it exists
    because `PageView` deliberately does not: that table keeps a salted
    `visitor_hash` so a person reading the site is never identifiable from the
    database. Nothing here changes that. A row is written only when the request
    already looked like automation — a bot user agent, or a path only a scanner
    would ask for — so someone browsing the guide is still never recorded by
    address.

    Kept short (`umbra.sentinel.PURGE_DAYS`), because the reason to hold it is
    to notice a pattern over days, not to keep a visitor log.
    """

    __tablename__ = "sentinel_observations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    # Why this request was treated as scanning — "bot_ua" / "probe_path".
    reason: Mapped[str] = mapped_column(String(32), default="", index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    method: Mapped[str] = mapped_column(String(16), default="GET")
    status: Mapped[int] = mapped_column(Integer, default=0)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    # Set once the address has been fingerprinted, so the cooldown can find it
    # without scanning every case.
    case_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)


_engine = None
_SessionLocal = None


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite:")


#: SQLite types for the model types we actually use. Only additive columns go
#: through here, so the mapping stays small on purpose.
log = logging.getLogger(__name__)

_SQLITE_TYPES = {
    "VARCHAR": "VARCHAR", "TEXT": "TEXT", "INTEGER": "INTEGER", "BIGINT": "INTEGER",
    "FLOAT": "REAL", "NUMERIC": "NUMERIC", "BOOLEAN": "BOOLEAN",
    "DATETIME": "TIMESTAMP", "JSON": "TEXT",
}


def _sqlite_reconcile(conn) -> list[str]:
    """Add every model column the live SQLite database is missing.

    Umbra grew three hand-written migrations — entities.verification,
    entities.merged_into_id, cases.owner_id — and then the listing lifecycle
    added phone_numbers.active. That one was written into _migrate_postgres and
    never mirrored here, so production (Postgres) was fine while every SQLite
    install died on `umbra phone check` with "no such column:
    phone_numbers.active". SQLite is what every `pip install umbra-osint` uses,
    so the audience that broke was the entire OSS CLI one.

    Hand-maintaining a list per column is how that happens. This reconciles the
    model against the database instead, so the next added column needs no
    migration written at all.

    Additive only. SQLite cannot ALTER a primary key, change a type, or add a
    UNIQUE or NOT NULL column without a default — those are reported by
    `_sqlite_structural_drift` rather than guessed at.
    """
    from sqlalchemy import inspect as sa_inspect

    insp = sa_inspect(conn)
    added: list[str] = []
    for name, table in Base.metadata.tables.items():
        if not insp.has_table(name):
            continue  # create_all handles brand-new tables
        live = {c["name"] for c in insp.get_columns(name)}
        pk = {c.name for c in table.primary_key.columns}
        for col in table.columns:
            if col.name in live or col.name in pk:
                continue
            if not col.nullable and col.default is None and col.server_default is None:
                continue  # cannot backfill a NOT NULL without a value
            if col.unique:
                continue  # ALTER cannot add UNIQUE in SQLite
            type_name = type(col.type).__name__.upper()
            sql_type = _SQLITE_TYPES.get(type_name)
            if sql_type is None:
                try:
                    sql_type = col.type.compile(dialect=conn.dialect)
                except Exception:  # noqa: BLE001
                    continue
            conn.execute(text(f"ALTER TABLE {name} ADD COLUMN {col.name} {sql_type}"))
            added.append(f"{name}.{col.name}")
    return added


def sqlite_structural_drift(conn) -> dict[str, list[str]]:
    """Tables whose shape changed in a way ALTER cannot fix (e.g. a new PK).

    Reported, never silently rebuilt — dropping a table to make a schema match
    would destroy data the operator collected, which is not a migration's call
    to make. `init_db` rebuilds only when the table is empty and therefore
    costs nothing.
    """
    from sqlalchemy import inspect as sa_inspect

    insp = sa_inspect(conn)
    out: dict[str, list[str]] = {}
    for name, table in Base.metadata.tables.items():
        if not insp.has_table(name):
            continue
        live = {c["name"] for c in insp.get_columns(name)}
        pk = {c.name for c in table.primary_key.columns}
        missing_pk = sorted(pk - live)
        if missing_pk:
            out[name] = missing_pk
    return out


def _migrate_sqlite(engine) -> None:
    """Lightweight SQLite migrations for additive columns/tables."""
    with engine.begin() as conn:
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(entities)")).fetchall()}
        if cols and "verification" not in cols:
            conn.execute(text("ALTER TABLE entities ADD COLUMN verification VARCHAR(32) DEFAULT 'unknown'"))
        if cols and "merged_into_id" not in cols:
            conn.execute(text("ALTER TABLE entities ADD COLUMN merged_into_id VARCHAR(32)"))

        # Case ownership: existing rows keep a NULL owner, which means
        # operator-owned (umbra.web.session).
        case_cols = {r[1] for r in conn.execute(text("PRAGMA table_info(cases)")).fetchall()}
        if case_cols and "owner_id" not in case_cols:
            conn.execute(text("ALTER TABLE cases ADD COLUMN owner_id VARCHAR(64)"))

        # The listing lifecycle (active / delisted_at / report source) shipped
        # one deploy after the phone tables. _migrate_postgres was updated and
        # this function was not — so production, on Postgres, was fine while
        # every SQLite install broke on `umbra phone check` with
        # "no such column: phone_numbers.active".
        #
        # SQLite is what every pip install of umbra-osint uses, so the surface
        # that got missed is the entire OSS CLI audience.
        phone_cols = {r[1] for r in conn.execute(text("PRAGMA table_info(phone_numbers)")).fetchall()}
        if phone_cols:
            if "active" not in phone_cols:
                conn.execute(text("ALTER TABLE phone_numbers ADD COLUMN active BOOLEAN DEFAULT 1"))
            if "delisted_at" not in phone_cols:
                conn.execute(text("ALTER TABLE phone_numbers ADD COLUMN delisted_at TIMESTAMP"))
        report_cols = {r[1] for r in conn.execute(text("PRAGMA table_info(phone_reports)")).fetchall()}
        if report_cols and "source" not in report_cols:
            conn.execute(text("ALTER TABLE phone_reports ADD COLUMN source VARCHAR(16) DEFAULT 'community'"))

        # Everything else, reconciled from the model rather than by hand.
        _sqlite_reconcile(conn)

        # A table whose primary key changed cannot be ALTERed into shape. Rebuild
        # it only when it holds nothing — an empty cache costs nothing to
        # recreate, and anything with rows is the operator's data and gets
        # reported instead.
        for name, missing_pk in sqlite_structural_drift(conn).items():
            rows = conn.execute(text(f"SELECT COUNT(*) FROM {name}")).scalar() or 0
            if rows:
                log.warning(
                    "schema drift in %s: missing primary key column(s) %s and %d row(s) "
                    "present — not rebuilding. Back the table up and recreate it.",
                    name, ", ".join(missing_pk), rows,
                )
                continue
            conn.execute(text(f"DROP TABLE {name}"))
            log.info("rebuilt empty table %s (primary key changed: %s)",
                     name, ", ".join(missing_pk))


def _migrate_postgres(engine) -> None:
    """Lightweight Postgres additive migrations (safe if columns already exist)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'entities'
                  ) THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'cases' AND column_name = 'owner_id'
                    ) THEN
                      ALTER TABLE cases ADD COLUMN owner_id VARCHAR(64);
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'entities' AND column_name = 'verification'
                    ) THEN
                      ALTER TABLE entities ADD COLUMN verification VARCHAR(32) DEFAULT 'unknown';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'entities' AND column_name = 'merged_into_id'
                    ) THEN
                      ALTER TABLE entities ADD COLUMN merged_into_id VARCHAR(32);
                    END IF;
                  END IF;
                  -- Phone community tables shipped one deploy before the
                  -- listing lifecycle did, so production has the tables without
                  -- these three columns. create_all never ALTERs.
                  IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'phone_numbers'
                  ) THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'phone_numbers' AND column_name = 'active'
                    ) THEN
                      ALTER TABLE phone_numbers ADD COLUMN active BOOLEAN DEFAULT TRUE;
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'phone_numbers' AND column_name = 'delisted_at'
                    ) THEN
                      ALTER TABLE phone_numbers ADD COLUMN delisted_at TIMESTAMPTZ;
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM information_schema.columns
                      WHERE table_name = 'phone_reports' AND column_name = 'source'
                    ) THEN
                      ALTER TABLE phone_reports ADD COLUMN source VARCHAR(16) DEFAULT 'community';
                    END IF;
                  END IF;
                END $$;
                """
            )
        )


def init_db(settings: Settings | None = None):
    global _engine, _SessionLocal
    settings = settings or get_settings()
    settings.ensure_dirs()
    url = settings.sqlalchemy_url

    connect_args: dict = {}
    if _is_sqlite(url):
        connect_args = {"check_same_thread": False}

    _engine = create_engine(
        url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    if _is_sqlite(url):

        @event.listens_for(_engine, "connect")
        def _fk(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    Base.metadata.create_all(_engine)
    if _is_sqlite(url):
        _migrate_sqlite(_engine)
    else:
        _migrate_postgres(_engine)

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _engine


def get_session():
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal()


def reset_engine() -> None:
    """Drop cached engine (tests / process restarts)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
