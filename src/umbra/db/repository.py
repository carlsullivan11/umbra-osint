from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from umbra.core.models import (
    CollectorResult,
    EdgeIn,
    EdgeType,
    EntityIn,
    EvidenceIn,
    new_id,
    utcnow,
)
from umbra.core.normalize import entity_key, normalize_value
from umbra.feeds.rss import content_hash
from umbra.db.schema import (
    AuditEvent,
    Case,
    Edge,
    Entity,
    Evidence,
    FeedItem,
    FeedSource,
    Job,
    OpsEvent,
    Run,
)


class Repository:
    def __init__(self, session: Session, raw_dir: Path):
        self.session = session
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    # --- cases ---
    def create_case(self, name: str, basis: str, note: str = "",
                    owner_id: str | None = None) -> Case:
        case = Case(
            id=new_id("c_"),
            name=name,
            authorization_basis=basis,
            authorization_note=note,
            owner_id=owner_id,
        )
        self.session.add(case)
        self.audit(case.id, "case.create", {"name": name, "basis": basis})
        self.session.commit()
        self.session.refresh(case)
        return case

    def get_case(self, case_id: str) -> Case | None:
        return self.session.get(Case, case_id)

    def list_cases(self, owner_id: str | None = None, *,
                   limit: int | None = None, offset: int = 0) -> list[Case]:
        """Every case, or only one owner's.

        `owner_id=None` means *no filter* — the operator view. A visitor always
        passes their own id, and cases with a NULL owner (CLI, or created before
        ownership existed) are deliberately excluded from that: they belong to
        the operator, not to whoever asks first.
        """
        stmt = select(Case).order_by(Case.created_at.desc())
        if owner_id is not None:
            stmt = stmt.where(Case.owner_id == owner_id)
        if limit is not None:
            stmt = stmt.limit(limit).offset(offset)
        return list(self.session.scalars(stmt))

    def count_cases(self, owner_id: str | None = None) -> int:
        """How many cases exist for this viewer — the total behind a page."""
        stmt = select(func.count()).select_from(Case)
        if owner_id is not None:
            stmt = stmt.where(Case.owner_id == owner_id)
        return int(self.session.scalar(stmt) or 0)

    def case_counts(self, case_ids: list[str]) -> dict[str, dict[str, int]]:
        """Entity and run counts for many cases, in two queries rather than 2N.

        The cases list used to count per case in a loop. With the sentinel
        opening cases hourly that is an unbounded query count on a page that
        only grows — 283 queries for the 141 cases that prompted this.
        """
        out = {cid: {"entities": 0, "runs": 0} for cid in case_ids}
        if not case_ids:
            return out
        for model, key in ((Entity, "entities"), (Run, "runs")):
            rows = self.session.execute(
                select(model.case_id, func.count())
                .where(model.case_id.in_(case_ids))
                .group_by(model.case_id)
            ).all()
            for case_id, total in rows:
                if case_id in out:
                    out[case_id][key] = int(total or 0)
        return out

    def count_since(self, since: datetime | None = None) -> dict[str, int]:
        """Searches run and entities mapped, optionally within a window.

        Merged entities are excluded: a merge is an operator saying "these are
        the same thing", so counting both halves would inflate the number.
        """
        case_q = select(func.count()).select_from(Case)
        ent_q = select(func.count()).select_from(Entity).where(Entity.merged_into_id.is_(None))
        if since is not None:
            case_q = case_q.where(Case.created_at >= since)
            ent_q = ent_q.where(Entity.first_seen >= since)
        return {
            "searches": int(self.session.scalar(case_q) or 0),
            "entities": int(self.session.scalar(ent_q) or 0),
        }

    def backdate_case_for_stats(self, case_id: str, when: datetime) -> bool:
        """Move a case and its entities back in time (tests/maintenance)."""
        case = self.get_case(case_id)
        if case is None:
            return False
        case.created_at = when
        for ent in self.session.scalars(select(Entity).where(Entity.case_id == case_id)):
            ent.first_seen = when
        self.session.commit()
        return True

    def delete_case(self, case_id: str, reason: str = "user_request") -> dict[str, int] | None:
        """Remove a case and everything that hangs off it. Returns the counts.

        Deletion has to reach the disk. The raw collector responses under
        ``data/raw/<case_id>/`` are the fullest copy of what was collected about
        the subject, and a rows-only delete leaves them there — which would make
        the deletion language in `docs/legal/PRIVACY.md` untrue.

        The audit trail is treated in two halves. The case's own audit events go
        with it: they quote the case name and seed, which *is* the subject. A
        tombstone stays behind holding the case id, the counts and why — every
        case carries an ``authorization_basis``, so a case that vanishes without
        trace is its own accountability problem.

        Returns ``None`` for an unknown case rather than raising: delete is
        idempotent, and a client retrying after a timeout must not get a 500.
        """
        import shutil

        case = self.session.get(Case, case_id)
        if case is None:
            return None

        report = {
            "entities": self.session.query(Entity).filter_by(case_id=case_id).count(),
            "edges": self.session.query(Edge).filter_by(case_id=case_id).count(),
            "evidence": self.session.query(Evidence).filter_by(case_id=case_id).count(),
            "runs": self.session.query(Run).filter_by(case_id=case_id).count(),
            "jobs": self.session.query(Job).filter_by(case_id=case_id).count(),
            "raw_files": 0,
        }

        raw_path = Path(self.raw_dir) / case_id
        if raw_path.exists():
            report["raw_files"] = sum(1 for p in raw_path.rglob("*") if p.is_file())
            shutil.rmtree(raw_path, ignore_errors=True)

        from umbra.db.schema import WatchItem

        # Order matters: edges reference entities, so they go first.
        for model in (Edge, Evidence, Job, Run, WatchItem, Entity, AuditEvent):
            self.session.query(model).filter_by(case_id=case_id).delete(
                synchronize_session=False)

        self.session.delete(case)
        self.session.add(AuditEvent(
            id=new_id("a_"),
            case_id=None,  # the row it would point at no longer exists
            action="case.delete",
            detail={"case_id": case_id, "reason": reason, **report},
        ))
        self.session.commit()
        return report

    def purge_cases_older_than(self, days: int, now: datetime | None = None) -> list[dict]:
        """Delete cases created more than ``days`` ago. ``0`` deletes nothing.

        Zero is the disabled state, not "everything is older than zero days" —
        the sweep is opt-in, and a self-hoster who upgrades must not lose work to
        a retention window they never set. See ``Settings.case_retention_days``.
        """
        if not days or days <= 0:
            return []
        cutoff = (now or utcnow()) - timedelta(days=days)
        stale = self.session.execute(
            select(Case.id).where(Case.created_at < cutoff)
        ).scalars().all()
        removed = []
        for case_id in stale:
            report = self.delete_case(case_id, reason="retention")
            if report is not None:
                removed.append({"case_id": case_id, **report})
        return removed

    def case_is_visible_to(self, case: Case, owner_id: str | None,
                           is_operator: bool = False) -> bool:
        """Ownership check for a single case."""
        if is_operator:
            return True
        if case.owner_id is None:
            return False  # operator-owned by definition
        return bool(owner_id) and case.owner_id == owner_id

    # --- audit ---
    # --- news feed (S14 / F1) ---
    def upsert_feed_source(
        self,
        name: str,
        url: str,
        kind: str = "rss",
        trust: float = 0.7,
        enabled: bool = True,
    ) -> FeedSource:
        """Add a source, or return the existing one for that URL.

        Deliberately does not re-enable a disabled source: seeding the default
        pack must never un-mute something the operator turned off.
        """
        existing = self.session.scalar(select(FeedSource).where(FeedSource.url == url))
        if existing:
            return existing
        source = FeedSource(
            id=new_id("fs_"), name=name, url=url, kind=kind,
            trust=trust, enabled=enabled,
        )
        self.session.add(source)
        self.session.commit()
        self.session.refresh(source)
        return source

    def list_feed_sources(self, enabled_only: bool = False) -> list[FeedSource]:
        stmt = select(FeedSource).order_by(FeedSource.name)
        if enabled_only:
            stmt = stmt.where(FeedSource.enabled.is_(True))
        return list(self.session.scalars(stmt))

    def set_feed_source_enabled(self, name_or_url: str, enabled: bool) -> bool:
        """Mute/unmute a source by URL or exact name. False if not found."""
        src = self.session.scalar(
            select(FeedSource).where(FeedSource.url == name_or_url)
        ) or self.session.scalar(
            select(FeedSource).where(FeedSource.name == name_or_url)
        )
        if src is None:
            return False
        src.enabled = enabled
        self.session.commit()
        return True

    def mark_feed_source_polled(
        self, source: FeedSource, status: str, error: str | None = None
    ) -> None:
        source.last_polled_at = utcnow()
        source.last_status = status
        source.last_error = error
        self.session.commit()

    def add_feed_items(self, source: FeedSource, items: Iterable[dict]) -> tuple[int, int]:
        """Store new items, skipping ones already seen. Returns (new, duplicates).

        Dedupe is on `content_hash` (a canonical-URL hash), so re-polling a feed
        and two sources syndicating one story both collapse to a single row.
        Each insert is committed on its own: a duplicate racing in from another
        poll must cost that one item, not the whole batch.
        """
        added = dupes = 0
        for item in items:
            url = (item.get("url") or "").strip()
            if not url:
                continue
            digest = content_hash(url)
            if self.session.scalar(select(FeedItem).where(FeedItem.content_hash == digest)):
                dupes += 1
                continue
            row = FeedItem(
                id=new_id("fi_"),
                source_id=source.id,
                external_id=(item.get("external_id") or None),
                url=url,
                title=(item.get("title") or url)[:2000],
                summary=item.get("summary") or "",
                # No pubDate is common. Dating it to the epoch would bury the
                # item forever, so it is dated to when we first saw it.
                published_at=item.get("published_at") or utcnow(),
                content_hash=digest,
            )
            self.session.add(row)
            try:
                self.session.commit()
                added += 1
            except IntegrityError:
                self.session.rollback()
                dupes += 1
        return added, dupes

    def count_feed_items(self) -> int:
        return int(self.session.scalar(select(func.count()).select_from(FeedItem)) or 0)

    def list_feed_items(
        self, since: datetime | None = None, limit: int = 200
    ) -> list[FeedItem]:
        # The source is eager-loaded because callers render these *after*
        # closing the session — a lazy `item.source` then raises
        # DetachedInstanceError, which shows up as a 500 on any non-empty feed
        # page while the empty page looks perfectly healthy.
        stmt = (
            select(FeedItem)
            .options(joinedload(FeedItem.source))
            .order_by(FeedItem.published_at.desc())
            .limit(limit)
        )
        if since is not None:
            stmt = stmt.where(FeedItem.published_at >= since)
        return list(self.session.scalars(stmt))

    # --- ops events (E1, docs/ERROR-REVIEW-CYCLE.md) ---
    def record_ops_event(
        self, severity: str, kind: str, title: str, detail: dict,
        fingerprint: str, source: str = "api",
    ) -> tuple[OpsEvent, bool, bool]:
        """Upsert by fingerprint. Returns (event, is_new, crossed_burst).

        `crossed_burst` fires exactly once, on the occurrence that reaches the
        escalation threshold — so a persistent failure speaks twice in total
        (first hit, then "this is not going away"), not once per occurrence.
        """
        from umbra.ops.events import ESCALATE_AT

        existing = self.session.scalar(
            select(OpsEvent).where(OpsEvent.fingerprint == fingerprint)
        )
        if existing is None:
            event = OpsEvent(
                id=new_id("oe_"), severity=severity, kind=kind, source=source,
                fingerprint=fingerprint, title=title, detail=detail,
                count=1, first_seen=utcnow(), last_seen=utcnow(), status="open",
            )
            self.session.add(event)
            self.session.commit()
            self.session.refresh(event)
            return event, True, False

        existing.count += 1
        existing.last_seen = utcnow()
        # Refresh the evidence, but never erase it: an emit that carries no
        # detail (a host script, a bare re-raise) must not wipe the traceback
        # the first occurrence captured. Found on prod during E1 verification.
        if detail:
            existing.detail = detail
        # A regression must not hide inside a closed row.
        reopened = existing.status in {"done", "wontfix"}
        if reopened:
            existing.status = "open"
            existing.resolution = None
        crossed = existing.count == ESCALATE_AT
        self.session.commit()
        self.session.refresh(existing)
        return existing, reopened, crossed

    def ops_event_is_muted(self, event: OpsEvent) -> bool:
        if not event.muted_until:
            return False
        until = event.muted_until
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > utcnow()

    def get_ops_event(self, event_id: str) -> OpsEvent | None:
        return self.session.get(OpsEvent, event_id)

    def list_ops_events(
        self,
        status: str | None = None,
        severity: str | None = None,
        needs_plan: bool = False,
        since: datetime | None = None,
        limit: int = 200,
    ) -> list[OpsEvent]:
        stmt = select(OpsEvent).order_by(OpsEvent.last_seen.desc()).limit(limit)
        if status:
            stmt = stmt.where(OpsEvent.status == status)
        if severity:
            stmt = stmt.where(OpsEvent.severity == severity)
        if needs_plan:
            # What the review job pulls: nobody has drafted a fix yet. Without
            # this it re-proposes the same fix every morning.
            stmt = stmt.where(OpsEvent.proposed_fix.is_(None))
        if since is not None:
            stmt = stmt.where(OpsEvent.last_seen >= since)
        return list(self.session.scalars(stmt))

    def set_ops_event_status(
        self, event_id: str, status: str, resolution: str | None = None
    ) -> bool:
        event = self.get_ops_event(event_id)
        if event is None:
            return False
        event.status = status
        if resolution is not None:
            event.resolution = resolution
        self.session.commit()
        return True

    def plan_ops_event(
        self, event_id: str, proposed_fix: str, priority: str | None = None
    ) -> bool:
        """Attach a draft fix. Deliberately does NOT change status: bots draft,
        humans decide."""
        event = self.get_ops_event(event_id)
        if event is None:
            return False
        event.proposed_fix = proposed_fix
        if priority:
            event.priority = priority
        self.session.commit()
        return True

    def mute_ops_event(self, event_id: str, until: datetime) -> bool:
        event = self.get_ops_event(event_id)
        if event is None:
            return False
        event.muted_until = until
        self.session.commit()
        return True

    def backdate_ops_event(self, event_id: str, when: datetime) -> bool:
        """Test/maintenance helper: move an event's clock back."""
        event = self.get_ops_event(event_id)
        if event is None:
            return False
        event.first_seen = when
        event.last_seen = when
        self.session.commit()
        return True

    def prune_ops_events(self, days: int = 30) -> int:
        """Drop closed events past the retention window.

        Detail carries paths, seed values and case ids — investigation data, so
        it does not live forever. Open events are never pruned: an unresolved
        problem is not old news no matter how long it has been failing.
        """
        cutoff = utcnow() - timedelta(days=days)
        rows = list(self.session.scalars(
            select(OpsEvent).where(
                OpsEvent.status.in_(("done", "wontfix")),
                OpsEvent.last_seen < cutoff,
            )
        ))
        for row in rows:
            self.session.delete(row)
        self.session.commit()
        return len(rows)

    def audit(self, case_id: str | None, action: str, detail: dict[str, Any] | None = None) -> None:
        self.session.add(
            AuditEvent(
                id=new_id("a_"),
                case_id=case_id,
                action=action,
                detail=detail or {},
            )
        )

    # --- entities / edges ---
    def get_entity_by_key(self, case_id: str, norm_key: str) -> Entity | None:
        return self.session.scalar(
            select(Entity).where(Entity.case_id == case_id, Entity.norm_key == norm_key)
        )

    def upsert_entity(self, case_id: str, ent: EntityIn, is_seed: bool = False) -> Entity:
        try:
            key = entity_key(ent.type, ent.value)
            value = normalize_value(ent.type, ent.value)
        except ValueError:
            # skip invalid/empty entities
            raise
        existing = self.get_entity_by_key(case_id, key)
        now = utcnow()
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, ent.confidence)
            if ent.display_name and not existing.display_name:
                existing.display_name = ent.display_name
            props = dict(existing.props or {})
            props.update(ent.props or {})
            existing.props = props
            if is_seed:
                existing.is_seed = True
            return existing

        row = Entity(
            id=new_id("e_"),
            case_id=case_id,
            type=ent.type.value,
            value=value,
            norm_key=key,
            display_name=ent.display_name,
            props=ent.props or {},
            confidence=ent.confidence,
            is_seed=is_seed,
            first_seen=now,
            last_seen=now,
        )
        self.session.add(row)
        return row

    def upsert_edge(self, case_id: str, edge: EdgeIn, id_by_key: dict[str, str]) -> Edge | None:
        src = id_by_key.get(edge.source_key)
        tgt = id_by_key.get(edge.target_key)
        if not src or not tgt or src == tgt:
            return None
        existing = self.session.scalar(
            select(Edge).where(
                Edge.case_id == case_id,
                Edge.source_id == src,
                Edge.target_id == tgt,
                Edge.rel == edge.rel.value,
            )
        )
        now = utcnow()
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, edge.confidence)
            props = dict(existing.props or {})
            props.update(edge.props or {})
            existing.props = props
            return existing
        row = Edge(
            id=new_id("g_"),
            case_id=case_id,
            source_id=src,
            target_id=tgt,
            rel=edge.rel.value,
            confidence=edge.confidence,
            props=edge.props or {},
            first_seen=now,
            last_seen=now,
        )
        self.session.add(row)
        return row

    def _store_raw(self, case_id: str, run_id: str | None, collector: str, raw: Any) -> tuple[str | None, str | None]:
        if raw is None:
            return None, None
        payload = raw if isinstance(raw, str) else json.dumps(raw, default=str, indent=2)
        digest = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
        rel = f"{case_id}/{run_id or 'norun'}/{collector}_{digest[:12]}.json"
        path = self.raw_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        return str(path), digest

    def add_evidence(
        self,
        case_id: str,
        run_id: str | None,
        ev: EvidenceIn,
        id_by_key: dict[str, str],
    ) -> Evidence:
        entity_id = id_by_key.get(ev.entity_key) if ev.entity_key else None
        raw_path, raw_hash = self._store_raw(case_id, run_id, ev.collector, ev.raw)
        row = Evidence(
            id=new_id("v_"),
            case_id=case_id,
            run_id=run_id,
            entity_id=entity_id,
            collector=ev.collector,
            source_name=ev.source_name,
            source_url=ev.source_url,
            summary=ev.summary,
            confidence=ev.confidence,
            raw_path=raw_path,
            raw_hash=raw_hash,
            observed_at=utcnow(),
        )
        self.session.add(row)
        return row

    def apply_result(
        self,
        case_id: str,
        run_id: str | None,
        result: CollectorResult,
    ) -> dict[str, int]:
        """Merge collector output; returns counts."""
        id_by_key: dict[str, str] = {
            e.norm_key: e.id
            for e in self.session.scalars(select(Entity).where(Entity.case_id == case_id))
        }
        new_entities = 0
        for ent in result.entities:
            try:
                key = entity_key(ent.type, ent.value)
            except ValueError:
                continue
            before = key in id_by_key
            try:
                row = self.upsert_entity(case_id, ent)
            except ValueError:
                continue
            self.session.flush()
            id_by_key[row.norm_key] = row.id
            if not before:
                new_entities += 1

        new_edges = 0
        for edge in result.edges:
            row = self.upsert_edge(case_id, edge, id_by_key)
            if row is not None:
                new_edges += 1

        new_ev = 0
        for ev in result.evidence:
            self.add_evidence(case_id, run_id, ev, id_by_key)
            new_ev += 1

        self.session.flush()
        return {"entities": new_entities, "edges": new_edges, "evidence": new_ev}

    def seed(self, case_id: str, ent: EntityIn) -> Entity:
        row = self.upsert_entity(case_id, ent, is_seed=True)
        self.audit(case_id, "case.seed", {"type": ent.type.value, "value": ent.value})
        self.session.commit()
        self.session.refresh(row)
        return row

    def list_entities(self, case_id: str, include_merged: bool = False) -> list[Entity]:
        q = select(Entity).where(Entity.case_id == case_id)
        if not include_merged:
            q = q.where((Entity.merged_into_id.is_(None)) | (Entity.merged_into_id == ""))
        return list(self.session.scalars(q.order_by(Entity.type, Entity.value)))

    def get_entity(self, entity_id: str) -> Entity | None:
        return self.session.get(Entity, entity_id)

    def find_entity(self, case_id: str, type_: str, value: str) -> Entity | None:
        from umbra.core.models import EntityType

        try:
            key = entity_key(EntityType(type_), value)
        except Exception:
            return None
        return self.get_entity_by_key(case_id, key)

    def set_verification(self, entity_id: str, status: str, note: str = "") -> Entity:
        if status not in {"unknown", "true", "false", "disputed"}:
            raise ValueError("status must be unknown|true|false|disputed")
        ent = self.get_entity(entity_id)
        if not ent:
            raise ValueError(f"entity not found: {entity_id}")
        ent.verification = status
        props = dict(ent.props or {})
        props["verification_note"] = note
        props["verification_status"] = status
        ent.props = props
        if status == "true":
            ent.confidence = max(ent.confidence, 0.95)
        elif status == "false":
            ent.confidence = min(ent.confidence, 0.15)
        self.audit(ent.case_id, "entity.verify", {"entity_id": entity_id, "status": status, "note": note})
        self.session.commit()
        self.session.refresh(ent)
        return ent

    def merge_entities(self, case_id: str, keep_id: str, drop_id: str) -> Entity:
        """Merge drop into keep: rewire edges, mark drop merged, combine props."""
        keep = self.get_entity(keep_id)
        drop = self.get_entity(drop_id)
        if not keep or not drop or keep.case_id != case_id or drop.case_id != case_id:
            raise ValueError("entities must exist on the same case")
        if keep.id == drop.id:
            raise ValueError("cannot merge entity into itself")

        # rewire edges
        edges = list(self.session.scalars(select(Edge).where(Edge.case_id == case_id)))
        for edge in edges:
            changed = False
            if edge.source_id == drop.id:
                edge.source_id = keep.id
                changed = True
            if edge.target_id == drop.id:
                edge.target_id = keep.id
                changed = True
            if changed and edge.source_id == edge.target_id:
                # drop self-loop unless meaningful
                self.session.delete(edge)

        # move evidence
        for ev in self.session.scalars(select(Evidence).where(Evidence.entity_id == drop.id)):
            ev.entity_id = keep.id

        props = dict(keep.props or {})
        props.update(drop.props or {})
        aliases = list(props.get("merged_aliases") or [])
        aliases.append({"type": drop.type, "value": drop.value, "id": drop.id})
        props["merged_aliases"] = aliases[-50:]
        keep.props = props
        keep.confidence = max(keep.confidence, drop.confidence)
        keep.is_seed = keep.is_seed or drop.is_seed
        if drop.verification == "true":
            keep.verification = "true"
        keep.last_seen = utcnow()

        drop.merged_into_id = keep.id
        drop.verification = drop.verification or "unknown"
        props_d = dict(drop.props or {})
        props_d["merged_into"] = keep.id
        drop.props = props_d

        # same_as edge
        self.upsert_edge(
            case_id,
            EdgeIn(
                source_key=drop.norm_key,
                target_key=keep.norm_key,
                rel=EdgeType.SAME_AS,
                confidence=0.99,
                props={"merged": True},
            ),
            {keep.norm_key: keep.id, drop.norm_key: keep.id},
        )

        self.audit(
            case_id,
            "entity.merge",
            {"keep": keep.id, "drop": drop.id, "keep_key": keep.norm_key, "drop_key": drop.norm_key},
        )
        self.session.commit()
        self.session.refresh(keep)
        return keep

    # --- watchlist ---
    def add_watch(
        self,
        entity_type: str,
        value: str,
        case_id: str | None = None,
        label: str = "",
    ):
        from umbra.db.schema import WatchItem

        item = WatchItem(
            id=new_id("w_"),
            case_id=case_id,
            entity_type=entity_type,
            value=value,
            label=label or value,
            enabled=True,
            last_snapshot={},
            last_diff={},
        )
        self.session.add(item)
        self.audit(case_id, "watch.add", {"type": entity_type, "value": value, "watch_id": item.id})
        self.session.commit()
        self.session.refresh(item)
        return item

    def list_watch(self, enabled_only: bool = False):
        from umbra.db.schema import WatchItem

        q = select(WatchItem).order_by(WatchItem.created_at.desc())
        if enabled_only:
            q = q.where(WatchItem.enabled.is_(True))
        return list(self.session.scalars(q))

    def get_watch(self, watch_id: str):
        from umbra.db.schema import WatchItem

        return self.session.get(WatchItem, watch_id)

    def update_watch_snapshot(self, watch_id: str, snapshot: dict, diff: dict) -> None:
        item = self.get_watch(watch_id)
        if not item:
            raise ValueError("watch not found")
        item.last_snapshot = snapshot
        item.last_diff = diff
        item.last_checked = utcnow()
        item.check_count = int(item.check_count or 0) + 1
        self.session.commit()

    def list_edges(self, case_id: str) -> list[Edge]:
        return list(self.session.scalars(select(Edge).where(Edge.case_id == case_id)))

    def list_evidence(self, case_id: str) -> list[Evidence]:
        return list(
            self.session.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.observed_at.desc()))
        )

    def list_audit(self, case_id: str) -> list[AuditEvent]:
        return list(
            self.session.scalars(
                select(AuditEvent).where(AuditEvent.case_id == case_id).order_by(AuditEvent.ts.desc())
            )
        )

    def create_run(self, case_id: str, depth: int, max_entities: int, collectors: list[str]) -> Run:
        run = Run(
            id=new_id("r_"),
            case_id=case_id,
            depth=depth,
            max_entities=max_entities,
            collectors=collectors,
            status="running",
            stats={},
        )
        self.session.add(run)
        self.audit(case_id, "run.start", {"run_id": run.id, "collectors": collectors, "depth": depth})
        self.session.commit()
        self.session.refresh(run)
        return run

    def finish_run(self, run: Run, status: str, stats: dict[str, Any]) -> None:
        run.status = status
        run.finished_at = utcnow()
        run.stats = stats
        self.audit(run.case_id, "run.finish", {"run_id": run.id, "status": status, "stats": stats})
        self.session.commit()

    # --- jobs (Phase B) --------------------------------------------------

    def enqueue_job(
        self,
        case_id: str,
        collectors: list[str],
        depth: int,
        max_entities: int,
        seed_value: str | None = None,
    ) -> Job:
        """Persist a unit of work. Durable by construction: the row is the
        queue, so a restart of the API or worker cannot lose it."""
        job = Job(
            id=new_id("j_"),
            case_id=case_id,
            status="queued",
            collectors=list(collectors or []),
            depth=depth,
            max_entities=max_entities,
            seed_value=seed_value,
            stats={},
        )
        self.session.add(job)
        self.audit(case_id, "job.enqueue",
                   {"job_id": job.id, "collectors": collectors, "depth": depth})
        self.session.commit()
        self.session.refresh(job)
        return job

    def claim_job(self, worker_id: str) -> Job | None:
        """Atomically take the oldest queued job, or return None.

        Exclusivity comes from the conditional UPDATE (`WHERE status='queued'`)
        and its rowcount, not from the preceding SELECT — so two workers racing
        on the same row cannot both win. This is portable: Postgres could use
        SELECT ... FOR UPDATE SKIP LOCKED, but the compare-and-set works
        identically on SQLite (used by the tests and local dev).
        """
        while True:
            candidate = self.session.execute(
                select(Job.id).where(Job.status == "queued").order_by(Job.created_at, Job.id).limit(1)
            ).scalar_one_or_none()
            if candidate is None:
                return None

            result = self.session.execute(
                update(Job)
                .where(Job.id == candidate, Job.status == "queued")
                .values(status="running", worker_id=worker_id, started_at=utcnow())
            )
            self.session.commit()
            if result.rowcount == 1:
                job = self.session.get(Job, candidate)
                self.audit(job.case_id, "job.claim", {"job_id": job.id, "worker": worker_id})
                self.session.commit()
                return job
            # Lost the race for this row; try the next one.

    def finish_job(self, job: Job, status: str, stats: dict[str, Any],
                   error: str | None = None) -> None:
        job.status = status
        job.stats = stats or {}
        job.error = error
        job.finished_at = utcnow()
        self.audit(job.case_id, "job.finish",
                   {"job_id": job.id, "status": status, "error": error})
        self.session.commit()

    def get_job(self, job_id: str) -> Job | None:
        return self.session.get(Job, job_id)

    def list_jobs(self, case_id: str) -> list[Job]:
        return list(
            self.session.scalars(
                select(Job).where(Job.case_id == case_id).order_by(Job.created_at.desc())
            )
        )

    def active_jobs(self, case_id: str) -> list[Job]:
        """Jobs the UI should show as in-flight (drives auto-refresh)."""
        return [j for j in self.list_jobs(case_id) if j.status in ("queued", "running")]

    def reap_orphaned_runs(self, older_than_s: float = 3 * 3600.0) -> int:
        """Close runs whose worker died before `finish_run` could be reached.

        Found in production: three cases sat at "running" for **120 hours** with
        every one of their jobs `ok`. A container restart mid-run — a deploy, in
        practice — kills the process between `create_run` and `finish_run`.
        `requeue_stale_jobs` rescues the *job*, which then completes; nothing
        closed the *run*, and the case page treats any run in `running` as work
        in progress, so it auto-refreshed forever telling a real visitor their
        investigation was still going.

        The status is `interrupted`, deliberately. `ok` would claim results
        nobody saw and make a truncated graph look complete; `failed` would
        claim a failure that was never observed.

        Elapsed time alone is not evidence of abandonment — a deep scan is slow
        — so a case with an active job is left alone however long it has been.
        """
        cutoff = utcnow() - timedelta(seconds=older_than_s)
        candidates = list(
            self.session.scalars(
                select(Run).where(Run.status == "running", Run.started_at <= cutoff)
            )
        )
        reaped = 0
        for run in candidates:
            if self.active_jobs(run.case_id):
                continue  # something is still working on this case
            run.status = "interrupted"
            run.finished_at = utcnow()
            run.stats = {
                **(run.stats or {}),
                "reaped": True,
                "reason": ("worker did not finish this run; closed by the sweep "
                           "after %.0fh" % (older_than_s / 3600)),
            }
            self.audit(run.case_id, "run.reaped",
                       {"run_id": run.id, "started_at": str(run.started_at)})
            reaped += 1
        if reaped:
            self.session.commit()
        return reaped

    def requeue_stale_jobs(self, older_than_s: float = 1800.0) -> int:
        """Rescue jobs abandoned by a worker that died mid-run.

        Without this a killed worker leaves the row 'running' forever and that
        case is stuck permanently. Only rows started longer ago than the
        threshold are touched, so healthy in-flight work is never disturbed.
        """
        cutoff = utcnow() - timedelta(seconds=older_than_s)
        stale = list(
            self.session.scalars(
                select(Job).where(Job.status == "running", Job.started_at <= cutoff)
            )
        )
        for job in stale:
            job.status = "queued"
            job.worker_id = None
            job.started_at = None
            self.audit(job.case_id, "job.requeue", {"job_id": job.id, "reason": "stale"})
        if stale:
            self.session.commit()
        return len(stale)

