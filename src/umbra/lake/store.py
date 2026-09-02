"""The owned lake corpus store (Certificate Transparency, extensible).

A standing, queryable certificate/domain index that Umbra owns — no external
API at query time. Separate from the per-case graph DB: the lake is reference
data shared across all cases. SQLite by default (``data/lake/lake.db``);
point ``UMBRA_LAKE_URL`` at Postgres to scale the same schema out later.

Schema:
- ``ct_cert``    one row per ingested CT entry (log + index unique)
- ``ct_domain``  one row per (cert, domain); ``rdn`` is the reversed name for
                 indexed subtree search
- ``ct_checkpoint``  per-log ingest position, so ingest is resumable
"""
from __future__ import annotations

import logging

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from umbra.lake.ct import CertRecord, reverse_domain


logger = logging.getLogger(__name__)


class LakeBase(DeclarativeBase):
    pass


class CtCert(LakeBase):
    __tablename__ = "ct_cert"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log: Mapped[str] = mapped_column(String(128), index=True)
    entry_index: Mapped[int] = mapped_column(Integer)
    entry_type: Mapped[int] = mapped_column(Integer)
    timestamp_ms: Mapped[int] = mapped_column(Integer)
    cn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial: Mapped[str | None] = mapped_column(String(80), nullable=True)
    not_before: Mapped[str | None] = mapped_column(String(40), nullable=True)
    not_after: Mapped[str | None] = mapped_column(String(40), nullable=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    fingerprint_sha1: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    seen_at: Mapped[str] = mapped_column(String(40))
    domains: Mapped[list["CtDomain"]] = relationship(
        back_populates="cert", cascade="all, delete-orphan"
    )
    __table_args__ = (UniqueConstraint("log", "entry_index", name="uq_ct_log_index"),)


class CtDomain(LakeBase):
    __tablename__ = "ct_domain"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cert_id: Mapped[int] = mapped_column(ForeignKey("ct_cert.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), index=True)
    rdn: Mapped[str] = mapped_column(String(255))
    cert: Mapped[CtCert] = relationship(back_populates="domains")
    __table_args__ = (Index("ix_ct_domain_rdn", "rdn"),)


class AbuseUrl(LakeBase):
    """One malicious URL from URLhaus, indexed by the host that serves it."""

    __tablename__ = "abuse_url"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048), unique=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    added: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    threat: Mapped[str | None] = mapped_column(String(80), nullable=True)
    tags: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reporter: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    seen_at: Mapped[str] = mapped_column(String(40))


class AbuseIoc(LakeBase):
    """A C2 / malware indicator. ThreatFox and Feodo share this table."""

    __tablename__ = "abuse_ioc"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feed: Mapped[str] = mapped_column(String(32), index=True)
    ioc: Mapped[str] = mapped_column(String(512))
    host: Mapped[str] = mapped_column(String(255), index=True)
    ioc_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    threat_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    malware: Mapped[str | None] = mapped_column(String(120), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    seen_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (UniqueConstraint("feed", "ioc", name="uq_abuse_ioc"),)


class AbuseCert(LakeBase):
    """An SSLBL-listed certificate. SSLBL is SHA1-only; ours are SHA256, so the
    join needs a SHA1 fingerprint carried alongside on the cert entity."""

    __tablename__ = "abuse_cert"
    sha1: Mapped[str] = mapped_column(String(40), primary_key=True)
    reason: Mapped[str | None] = mapped_column(String(160), nullable=True)
    malware: Mapped[str | None] = mapped_column(String(120), nullable=True)
    listed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    seen_at: Mapped[str] = mapped_column(String(40))


class CryptoLabel(LakeBase):
    """A label about one on-chain address, from one source.

    `active` is the load-bearing column. OFAC *removes* entries — Tornado Cash
    was designated in 2022 and delisted in 2025 — and an address still labelled
    `sanctioned_ofac` after removal is not a stale cache entry, it is a false
    accusation of sanctions evasion from a tool whose whole pitch is provenance.

    A sync is therefore a full-file reconciliation per source: present means
    active, absent means delisted with a date, and nothing is deleted. "This was
    sanctioned until March" is a true and useful statement that an append-only
    cache cannot make.
    """

    __tablename__ = "crypto_label"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain: Mapped[str] = mapped_column(String(16), index=True)
    address: Mapped[str] = mapped_column(String(128), index=True)
    tag: Mapped[str] = mapped_column(String(40), index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    props: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))
    delisted_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    __table_args__ = (
        UniqueConstraint("chain", "address", "tag", "source", name="uq_crypto_label"),
    )


class CryptoTransfer(LakeBase):
    """A transfer that touched an address Umbra cares about.

    Targeted, not exhaustive. USDT alone is ~1.3M transfers a day — indexing
    everything would be ~47 GB a year for one token against a 5 GB/year budget,
    and would be a worse copy of a public database. Keeping only what touches a
    labelled or watched address is what makes this both affordable and worth
    having.
    """

    __tablename__ = "crypto_transfer"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain: Mapped[str] = mapped_column(String(16), index=True)
    txid: Mapped[str] = mapped_column(String(80), index=True)
    log_index: Mapped[int] = mapped_column(Integer, default=0)
    from_addr: Mapped[str] = mapped_column(String(128), index=True)
    to_addr: Mapped[str] = mapped_column(String(128), index=True)
    asset: Mapped[str] = mapped_column(String(64))
    contract: Mapped[str | None] = mapped_column(String(128), nullable=True)
    amount_raw: Mapped[str] = mapped_column(String(80))  # uint256 exceeds BIGINT
    decimals: Mapped[int] = mapped_column(Integer, default=0)
    block_number: Mapped[int] = mapped_column(Integer, index=True)
    seen_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (
        UniqueConstraint("chain", "txid", "log_index", name="uq_crypto_transfer"),
    )


class CryptoTailCheckpoint(LakeBase):
    """How far the head-follower has read, per chain. Resumable by design."""

    __tablename__ = "crypto_tail_checkpoint"
    chain: Mapped[str] = mapped_column(String(16), primary_key=True)
    last_block: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[str] = mapped_column(String(40))


class CryptoLabelSync(LakeBase):
    """When each label source last reconciled, and how many it carried."""

    __tablename__ = "crypto_label_sync"
    source: Mapped[str] = mapped_column(String(40), primary_key=True)
    synced_at: Mapped[str] = mapped_column(String(40))
    active_rows: Mapped[int] = mapped_column(Integer, default=0)


class AbuseSync(LakeBase):
    """When each feed last loaded. Without this, "no rows" and "never fetched"
    are the same answer, and one of them means clean while the other does not."""

    __tablename__ = "abuse_sync"
    feed: Mapped[str] = mapped_column(String(32), primary_key=True)
    synced_at: Mapped[str] = mapped_column(String(40))
    rows: Mapped[int] = mapped_column(Integer, default=0)


class CtCheckpoint(LakeBase):
    __tablename__ = "ct_checkpoint"
    log: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_index: Mapped[int] = mapped_column(Integer)
    tree_size: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[str] = mapped_column(String(40))


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class LakeStore:
    """Owns the lake engine/session and the CT ingest/query operations."""

    def __init__(self, url: str):
        self.engine = create_engine(url, future=True)
        LakeBase.metadata.create_all(self.engine)
        # create_all does not ALTER an existing table, and production already
        # holds thousands of certificates — without this the new column would
        # simply never appear there.
        self._migrate()
        self._Session = sessionmaker(bind=self.engine, future=True)

    def _migrate(self) -> None:
        """Additive migrations for a lake created before a column existed."""
        added = (
            ("fingerprint_sha256", "VARCHAR(64)"),
            ("fingerprint_sha1", "VARCHAR(40)"),
        )
        try:
            with self.engine.begin() as conn:
                dialect = self.engine.dialect.name
                if dialect == "sqlite":
                    cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(ct_cert)")}
                else:
                    cols = {r[0] for r in conn.exec_driver_sql(
                        "SELECT column_name FROM information_schema.columns"
                        " WHERE table_name = 'ct_cert'")}
                if not cols:
                    return
                for name, ddl in added:
                    if name not in cols:
                        conn.exec_driver_sql(f"ALTER TABLE ct_cert ADD COLUMN {name} {ddl}")
        except Exception:  # noqa: BLE001 - a lake that cannot migrate still reads
            logger.warning("lake migration skipped", exc_info=True)

    @classmethod
    def from_settings(cls, settings) -> "LakeStore":
        url = getattr(settings, "lake_url", None)
        if not url:
            lake_dir = Path(settings.data_dir) / "lake"
            lake_dir.mkdir(parents=True, exist_ok=True)
            url = f"sqlite:///{lake_dir / 'lake.db'}"
        return cls(url)

    # --- ingest ----------------------------------------------------------

    def get_checkpoint(self, log: str) -> int | None:
        with self._Session() as s:
            cp = s.get(CtCheckpoint, log)
            return cp.last_index if cp else None

    def set_checkpoint(self, log: str, last_index: int, tree_size: int) -> None:
        with self._Session() as s:
            cp = s.get(CtCheckpoint, log)
            if cp is None:
                cp = CtCheckpoint(log=log, last_index=last_index,
                                  tree_size=tree_size, updated_at=_now())
                s.add(cp)
            else:
                cp.last_index = last_index
                cp.tree_size = tree_size
                cp.updated_at = _now()
            s.commit()

    def add_records(self, log: str, start_index: int,
                    records: Iterable[CertRecord | None]) -> tuple[int, int]:
        """Persist parsed records for consecutive entries starting at
        ``start_index``. Returns (certs_added, domains_added). Duplicate
        (log, entry_index) rows are skipped idempotently."""
        certs = domains = 0
        with self._Session() as s:
            existing = {
                r[0] for r in s.execute(
                    select(CtCert.entry_index).where(CtCert.log == log)
                    .where(CtCert.entry_index >= start_index)
                ).all()
            }
            for offset, rec in enumerate(records):
                idx = start_index + offset
                if rec is None or idx in existing:
                    continue
                cert = CtCert(
                    log=log, entry_index=idx, entry_type=rec.entry_type,
                    timestamp_ms=rec.timestamp_ms, cn=(rec.cn or None),
                    issuer=rec.issuer, serial=rec.serial,
                    not_before=rec.not_before, not_after=rec.not_after,
                    fingerprint_sha256=getattr(rec, "fingerprint_sha256", None),
                    fingerprint_sha1=getattr(rec, "fingerprint_sha1", None),
                    seen_at=_now(),
                )
                for d in rec.domains:
                    cert.domains.append(CtDomain(name=d, rdn=reverse_domain(d)))
                    domains += 1
                s.add(cert)
                certs += 1
            s.commit()
        return certs, domains

    # --- query (no external API) ----------------------------------------

    def search(self, query: str, *, exact: bool = False, limit: int = 200) -> list[dict]:
        """Return certs whose domains match ``query`` from the owned corpus.

        Default is subtree: ``example.com`` returns the apex and every
        subdomain (and wildcard) ever seen, via the reversed-name index.
        """
        q = (query or "").strip().strip(".").lower()
        if not q:
            return []
        with self._Session() as s:
            stmt = select(CtDomain).join(CtCert)
            if exact:
                stmt = stmt.where(CtDomain.name == q)
            else:
                rq = reverse_domain(q)
                stmt = stmt.where(
                    (CtDomain.name == q) | (CtDomain.rdn == rq)
                    | (CtDomain.rdn.like(rq + ".%"))
                )
            stmt = stmt.order_by(CtCert.timestamp_ms.desc()).limit(limit)
            rows = s.execute(stmt).scalars().all()
            out = []
            for d in rows:
                c = d.cert
                out.append({
                    "domain": d.name, "log": c.log, "entry_index": c.entry_index,
                    "issuer": c.issuer, "cn": c.cn, "not_before": c.not_before,
                    "not_after": c.not_after, "serial": c.serial,
                    "fingerprint_sha256": c.fingerprint_sha256,
                    "fingerprint_sha1": getattr(c, "fingerprint_sha1", None),
                })
            return out

    def distinct_subdomains(self, query: str, limit: int = 1000) -> list[str]:
        q = (query or "").strip().strip(".").lower()
        rq = reverse_domain(q)
        with self._Session() as s:
            rows = s.execute(
                select(CtDomain.name).where(
                    (CtDomain.name == q) | (CtDomain.rdn == rq)
                    | (CtDomain.rdn.like(rq + ".%"))
                ).distinct().limit(limit)
            ).all()
        return sorted({r[0] for r in rows})

    # --- abuse.ch lake ---------------------------------------------------

    def abuse_upsert(self, feed: str, rows: list) -> int:
        """Merge one feed's rows in and record that the feed was synced.

        Upsert rather than replace: the abuse.ch exports are rolling windows, so
        replacing would throw away everything that aged out — which is precisely
        the history that makes owning the data worth anything.
        """
        now = _now()
        with self._Session() as s:
            for row in rows:
                if hasattr(row, "sha1"):
                    existing = s.get(AbuseCert, row.sha1)
                    if existing is None:
                        s.add(AbuseCert(sha1=row.sha1, reason=row.reason,
                                        malware=row.malware,
                                        listed_at=row.listed_at, seen_at=now))
                    else:
                        existing.reason = row.reason
                        existing.malware = row.malware
                        existing.seen_at = now
                elif hasattr(row, "url"):
                    existing = s.execute(
                        select(AbuseUrl).where(AbuseUrl.url == row.url)
                    ).scalar_one_or_none()
                    if existing is None:
                        s.add(AbuseUrl(
                            url=row.url, host=row.host, added=row.added,
                            status=row.status, threat=row.threat, tags=row.tags,
                            reporter=row.reporter, reference=row.reference,
                            seen_at=now))
                    else:
                        # A URL coming back online is the news in this feed.
                        existing.status = row.status
                        existing.tags = row.tags
                        existing.seen_at = now
                else:
                    existing = s.execute(
                        select(AbuseIoc).where(AbuseIoc.feed == row.feed,
                                               AbuseIoc.ioc == row.ioc)
                    ).scalar_one_or_none()
                    if existing is None:
                        s.add(AbuseIoc(
                            feed=row.feed, ioc=row.ioc, host=row.host,
                            ioc_type=row.ioc_type, threat_type=row.threat_type,
                            malware=row.malware, confidence=row.confidence,
                            tags=row.tags, first_seen=row.first_seen,
                            reference=row.reference, seen_at=now))
                    else:
                        existing.confidence = row.confidence
                        existing.malware = row.malware or existing.malware
                        existing.seen_at = now
            mark = s.get(AbuseSync, feed)
            if mark is None:
                s.add(AbuseSync(feed=feed, synced_at=now, rows=len(rows)))
            else:
                mark.synced_at = now
                mark.rows = len(rows)
            s.commit()
        return len(rows)

    def abuse_feed_synced_at(self, feed: str) -> str | None:
        with self._Session() as s:
            mark = s.get(AbuseSync, feed)
            return mark.synced_at if mark else None

    def abuse_urls_for_host(self, host: str, limit: int = 50) -> list[dict]:
        h = (host or "").strip().strip(".").lower()
        if not h:
            return []
        with self._Session() as s:
            rows = s.execute(
                select(AbuseUrl).where(AbuseUrl.host == h)
                .order_by(AbuseUrl.added.desc()).limit(limit)
            ).scalars().all()
            return [{"url": r.url, "host": r.host, "added": r.added,
                     "status": r.status, "threat": r.threat, "tags": r.tags,
                     "reporter": r.reporter, "reference": r.reference}
                    for r in rows]

    def abuse_iocs_for_host(self, host: str, limit: int = 50) -> list[dict]:
        h = (host or "").strip().strip(".").lower()
        if not h:
            return []
        with self._Session() as s:
            rows = s.execute(
                select(AbuseIoc).where(AbuseIoc.host == h)
                .order_by(AbuseIoc.confidence.desc()).limit(limit)
            ).scalars().all()
            return [{"feed": r.feed, "ioc": r.ioc, "host": r.host,
                     "ioc_type": r.ioc_type, "threat_type": r.threat_type,
                     "malware": r.malware, "confidence": r.confidence,
                     "tags": r.tags, "first_seen": r.first_seen,
                     "reference": r.reference}
                    for r in rows]

    def abuse_distinct_ip_hosts(self, limit: int = 200) -> list[str]:
        """Hosts in the abuse.ch lake that look like bare IP addresses.

        Used by Phase B corpus intake — not a live scan of the internet.
        Prefers Feodo/ThreatFox IOC hosts, then URLhaus hosts.
        """
        import ipaddress

        out: list[str] = []
        seen: set[str] = set()

        def _take(host: str | None) -> None:
            h = (host or "").strip().lower()
            if not h or h in seen:
                return
            # strip :port for IPv4
            if h.count(":") == 1 and "." in h:
                h = h.split(":", 1)[0]
            try:
                ipaddress.ip_address(h)
            except ValueError:
                return
            seen.add(h)
            out.append(h)

        with self._Session() as s:
            for row in s.execute(
                select(AbuseIoc.host).where(AbuseIoc.host.is_not(None))
                .order_by(AbuseIoc.seen_at.desc()).limit(limit * 5)
            ).all():
                _take(row[0])
                if len(out) >= limit:
                    return out
            for row in s.execute(
                select(AbuseUrl.host).where(AbuseUrl.host.is_not(None))
                .order_by(AbuseUrl.seen_at.desc()).limit(limit * 5)
            ).all():
                _take(row[0])
                if len(out) >= limit:
                    return out
        return out

    def abuse_distinct_domain_hosts(self, limit: int = 20_000) -> list[str]:
        """Distinct hosts that are not bare IPs (for DNS blocklists)."""
        import ipaddress

        out: list[str] = []
        seen: set[str] = set()

        def _take(host: str | None) -> None:
            h = (host or "").strip().lower().rstrip(".")
            if not h or h in seen:
                return
            if h.count(":") == 1 and "." in h:
                h = h.split(":", 1)[0]
            try:
                ipaddress.ip_address(h)
                return
            except ValueError:
                pass
            if "." not in h:
                return
            seen.add(h)
            out.append(h)

        with self._Session() as s:
            for row in s.execute(
                select(AbuseUrl.host).where(AbuseUrl.host.is_not(None))
                .order_by(AbuseUrl.seen_at.desc()).limit(limit * 3)
            ).all():
                _take(row[0])
                if len(out) >= limit:
                    return out
            for row in s.execute(
                select(AbuseIoc.host).where(AbuseIoc.host.is_not(None))
                .order_by(AbuseIoc.seen_at.desc()).limit(limit * 3)
            ).all():
                _take(row[0])
                if len(out) >= limit:
                    return out
        return out

    def abuse_all_hosts(self, limit: int = 50_000) -> list[str]:
        """All distinct hosts (domains + IPs) from urlhaus/ioc tables."""
        out: list[str] = []
        seen: set[str] = set()
        with self._Session() as s:
            for model in (AbuseIoc, AbuseUrl):
                for row in s.execute(
                    select(model.host).where(model.host.is_not(None))
                    .order_by(model.seen_at.desc()).limit(limit * 2)
                ).all():
                    h = (row[0] or "").strip().lower()
                    if not h or h in seen:
                        continue
                    seen.add(h)
                    out.append(h)
                    if len(out) >= limit:
                        return out
        return out

    def abuse_cert(self, sha1: str) -> dict | None:
        f = (sha1 or "").strip().lower().replace(":", "")
        if not f:
            return None
        with self._Session() as s:
            row = s.get(AbuseCert, f)
            if row is None:
                return None
            return {"sha1": row.sha1, "reason": row.reason,
                    "malware": row.malware, "listed_at": row.listed_at}

    # --- crypto labels ---------------------------------------------------

    def crypto_labels(self, chain: str, address: str, *,
                      include_delisted: bool = False) -> list[dict]:
        """Labels for one address. Delisted ones are excluded by default.

        A caller asking "is this sanctioned" must not get a yes out of history:
        OFAC removes entries, and the answer has to reflect the current list.
        """
        chain = (chain or "").strip().lower()
        candidates = {(address or "").strip(), (address or "").strip().lower()}
        with self._Session() as s:
            stmt = select(CryptoLabel).where(
                CryptoLabel.chain == chain,
                CryptoLabel.address.in_(candidates),
            )
            if not include_delisted:
                stmt = stmt.where(CryptoLabel.active.is_(True))
            rows = s.execute(stmt.order_by(CryptoLabel.confidence.desc())).scalars().all()
            return [{
                "chain": r.chain, "address": r.address, "tag": r.tag,
                "source": r.source, "confidence": r.confidence,
                "summary": r.summary, "url": r.url, "props": r.props or {},
                "active": bool(r.active), "first_seen": r.first_seen,
                "last_seen": r.last_seen, "delisted_at": r.delisted_at,
            } for r in rows]

    def crypto_replace_source(self, source: str, rows: list[dict]) -> dict:
        """Reconcile one source against a full snapshot. Returns counts.

        Present in `rows` means active; absent means delisted with a date;
        nothing is deleted. Scoped to `source` so one feed going quiet cannot
        delist another's entries.
        """
        now = _now()
        seen: set[tuple[str, str, str]] = set()
        added = refreshed = delisted = 0
        with self._Session() as s:
            existing = {
                (r.chain, r.address, r.tag): r
                for r in s.execute(
                    select(CryptoLabel).where(CryptoLabel.source == source)
                ).scalars()
            }
            for row in rows:
                key = (row["chain"], row["address"], row["tag"])
                if key in seen:
                    # The live SDN file lists some addresses under more than one
                    # entry. A second row for the same key would violate the
                    # unique constraint and add nothing — the first already
                    # carries the tag and source.
                    continue
                seen.add(key)
                current = existing.get(key)
                if current is None:
                    s.add(CryptoLabel(
                        chain=row["chain"], address=row["address"], tag=row["tag"],
                        source=source, confidence=row.get("confidence", 0.5),
                        summary=row.get("summary"), url=row.get("url"),
                        props=row.get("props") or {}, active=True,
                        first_seen=now, last_seen=now, delisted_at=None))
                    added += 1
                else:
                    current.last_seen = now
                    current.confidence = row.get("confidence", current.confidence)
                    current.summary = row.get("summary", current.summary)
                    current.props = row.get("props") or current.props
                    if not current.active:
                        current.active = True
                        current.delisted_at = None
                    refreshed += 1
            for key, row in existing.items():
                if key not in seen and row.active:
                    row.active = False
                    row.delisted_at = now
                    delisted += 1

            mark = s.get(CryptoLabelSync, source)
            if mark is None:
                s.add(CryptoLabelSync(source=source, synced_at=now,
                                      active_rows=len(seen)))
            else:
                mark.synced_at = now
                mark.active_rows = len(seen)
            s.commit()
        return {"added": added, "refreshed": refreshed, "delisted": delisted,
                "active": len(seen)}

    def crypto_labelled_addresses(self, chain: str) -> list[str]:
        """Active labelled addresses on one chain — the tail's watch set."""
        with self._Session() as s:
            return list(s.execute(
                select(CryptoLabel.address).where(
                    CryptoLabel.chain == (chain or "").lower(),
                    CryptoLabel.active.is_(True),
                ).distinct()).scalars())

    def crypto_store_transfers(self, rows: list[dict]) -> int:
        """Store transfers not seen before. Returns how many were new."""
        if not rows:
            return 0
        now = _now()
        added = 0
        with self._Session() as s:
            for row in rows:
                key = (row["chain"], row["txid"], row.get("log_index", 0))
                exists = s.execute(
                    select(CryptoTransfer.id).where(
                        CryptoTransfer.chain == key[0],
                        CryptoTransfer.txid == key[1],
                        CryptoTransfer.log_index == key[2])
                ).scalar_one_or_none()
                if exists is not None:
                    continue
                s.add(CryptoTransfer(
                    chain=row["chain"], txid=row["txid"],
                    log_index=row.get("log_index", 0),
                    from_addr=row["from_addr"], to_addr=row["to_addr"],
                    asset=row.get("asset", ""), contract=row.get("contract"),
                    # uint256 does not fit a BIGINT; stored as text and never
                    # summed in SQL.
                    amount_raw=str(row.get("amount_raw", 0)),
                    decimals=row.get("decimals", 0),
                    block_number=row.get("block_number", 0), seen_at=now))
                added += 1
            if added:
                s.commit()
        return added

    def crypto_transfers_for(self, chain: str, address: str,
                             limit: int = 200) -> list[dict]:
        addr = (address or "").strip().lower()
        with self._Session() as s:
            rows = s.execute(
                select(CryptoTransfer).where(
                    CryptoTransfer.chain == (chain or "").lower(),
                    (CryptoTransfer.from_addr == addr)
                    | (CryptoTransfer.to_addr == addr),
                ).order_by(CryptoTransfer.block_number.desc()).limit(limit)
            ).scalars().all()
            return [{"chain": r.chain, "txid": r.txid, "log_index": r.log_index,
                     "from_addr": r.from_addr, "to_addr": r.to_addr,
                     "asset": r.asset, "contract": r.contract,
                     "amount_raw": r.amount_raw, "decimals": r.decimals,
                     "block_number": r.block_number} for r in rows]

    def crypto_recent_transfers(self, limit: int = 50) -> list[dict]:
        with self._Session() as s:
            rows = s.execute(
                select(CryptoTransfer)
                .order_by(CryptoTransfer.block_number.desc()).limit(limit)
            ).scalars().all()
            return [{"chain": r.chain, "txid": r.txid, "from_addr": r.from_addr,
                     "to_addr": r.to_addr, "asset": r.asset,
                     "amount_raw": r.amount_raw, "decimals": r.decimals,
                     "block_number": r.block_number} for r in rows]

    def crypto_tail_checkpoint(self, chain: str) -> int | None:
        with self._Session() as s:
            row = s.get(CryptoTailCheckpoint, (chain or "").lower())
            return row.last_block if row else None

    def crypto_set_tail_checkpoint(self, chain: str, block: int) -> None:
        with self._Session() as s:
            row = s.get(CryptoTailCheckpoint, (chain or "").lower())
            if row is None:
                s.add(CryptoTailCheckpoint(chain=(chain or "").lower(),
                                           last_block=int(block),
                                           updated_at=_now()))
            else:
                row.last_block = int(block)
                row.updated_at = _now()
            s.commit()

    def crypto_transfer_stats(self) -> dict:
        with self._Session() as s:
            total = s.execute(
                select(func.count()).select_from(CryptoTransfer)).scalar_one()
            checkpoints = {c.chain: {"last_block": c.last_block,
                                     "updated_at": c.updated_at}
                           for c in s.execute(
                               select(CryptoTailCheckpoint)).scalars()}
        return {"transfers": int(total), "checkpoints": checkpoints}

    def crypto_label_stats(self) -> dict:
        with self._Session() as s:
            active = s.execute(
                select(func.count()).select_from(CryptoLabel)
                .where(CryptoLabel.active.is_(True))).scalar_one()
            delisted = s.execute(
                select(func.count()).select_from(CryptoLabel)
                .where(CryptoLabel.active.is_(False))).scalar_one()
            by_chain = {
                chain: int(n) for chain, n in s.execute(
                    select(CryptoLabel.chain, func.count())
                    .where(CryptoLabel.active.is_(True))
                    .group_by(CryptoLabel.chain)).all()
            }
            sources = {}
            for mark in s.execute(select(CryptoLabelSync)).scalars():
                sources[mark.source] = {"synced_at": mark.synced_at,
                                        "active": mark.active_rows}
        return {"active": int(active), "delisted": int(delisted),
                "by_chain": by_chain, "sources": sources}

    def abuse_stats(self) -> dict:
        with self._Session() as s:
            urls = s.execute(select(func.count()).select_from(AbuseUrl)).scalar_one()
            iocs = s.execute(select(func.count()).select_from(AbuseIoc)).scalar_one()
            certs = s.execute(select(func.count()).select_from(AbuseCert)).scalar_one()
            feeds = {m.feed: {"synced_at": m.synced_at, "rows": m.rows}
                     for m in s.execute(select(AbuseSync)).scalars().all()}
        return {"urls": urls, "iocs": iocs, "certs": certs, "feeds": feeds}

    def stats(self) -> dict:
        with self._Session() as s:
            certs = s.execute(select(func.count()).select_from(CtCert)).scalar_one()
            domains = s.execute(
                select(func.count(func.distinct(CtDomain.name)))
            ).scalar_one()
            cps = s.execute(select(CtCheckpoint)).scalars().all()
            checkpoints = {
                cp.log: {"last_index": cp.last_index, "tree_size": cp.tree_size,
                         "updated_at": cp.updated_at}
                for cp in cps
            }
        return {"certs": certs, "distinct_domains": domains, "checkpoints": checkpoints}
