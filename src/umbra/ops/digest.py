"""S3/S4 digest (E2).

Quality signals never page — that is the point of them. But an event nobody
reads is the same as an event nobody recorded, so once an hour the unread ones
are summarised into a single message.

Two rules keep it worth reading: it says nothing when there is nothing to say
(a digest that arrives every hour saying "nothing" trains you to ignore the one
that says something), and it skips anything that already paged.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from umbra.core.config import get_settings
from umbra.ops.notify import notify

logger = logging.getLogger(__name__)

DIGEST_SEVERITIES = ("S3", "S4")

# A signal you have already dispositioned is noise on the next pass. `ack`
# stays — it means "seen, not dealt with".
OPEN_STATUSES = ("open", "ack", "planned", "in_progress")


def build_digest(hours: int = 1) -> str | None:
    """Text for the window, or None when there is nothing new."""
    from umbra.db.repository import Repository
    from umbra.db.schema import get_session, init_db

    settings = get_settings()
    init_db(settings)
    session = get_session()
    try:
        repo = Repository(session, settings.raw_dir)
        since = datetime.now(tz=timezone.utc) - timedelta(hours=max(1, hours))
        rows = [
            e for e in repo.list_ops_events(status=None, since=since, limit=200)
            if e.severity in DIGEST_SEVERITIES
            and e.status in OPEN_STATUSES
            and not repo.ops_event_is_muted(e)
        ]
        if not rows:
            return None

        by_kind: dict[str, list] = {}
        for e in rows:
            by_kind.setdefault(e.kind, []).append(e)

        lines = [f"🔵 Umbra quality digest · last {hours}h · {len(rows)} signal(s)"]
        for kind, events in sorted(by_kind.items()):
            total = sum(e.count for e in events)
            lines.append(f"\n{kind} ×{total}")
            for e in events[:3]:
                lines.append(f"  {e.id} {e.title[:80]}")
            if len(events) > 3:
                lines.append(f"  …and {len(events) - 3} more")
        lines.append("\ntriage: umbra ops events --severity S3")
        return "\n".join(lines)
    finally:
        session.close()


def send_digest(hours: int = 1) -> bool:
    """Send the digest if there is one. Returns whether anything was sent."""
    try:
        text = build_digest(hours=hours)
    except Exception:  # noqa: BLE001 - a digest must not become an incident
        logger.exception("failed to build ops digest")
        return False
    if not text:
        return False
    notify(text)
    return True
