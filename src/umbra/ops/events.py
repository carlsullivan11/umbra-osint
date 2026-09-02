"""`emit()` — the one entry point every detector calls (phase E1).

Contract, in priority order:

1. **Never raise.** This runs on the failure path. A bug here that turns a
   handled 500 into an unhandled one, or kills a worker mid-job, is worse than
   having no error tracking at all. Every failure mode returns `None`.
2. **One bug is one event.** Repeats increment a count on the open row; only a
   new fingerprint or a burst crossing `ESCALATE_AT` sends an alert.
3. **No secrets, bounded size.** Detail is redacted and truncated on the way in.

Severity → alerting (docs/ERROR-REVIEW-CYCLE.md §6): S0/S1 page immediately,
S2 pages on a new fingerprint or a burst, S3/S4 are recorded for the digest and
never page.
"""
from __future__ import annotations

import json
import logging

from umbra.core.config import get_settings
from umbra.ops.notify import fingerprint, format_alert, notify, redact

logger = logging.getLogger(__name__)

# A fingerprint that keeps firing says something changed; speak once more.
ESCALATE_AT = 10

# A stack trace or an HTML body can be megabytes. The row is a pointer to the
# problem, not an archive of it.
MAX_DETAIL_CHARS = 4000

PAGING_SEVERITIES = {"S0", "S1", "S2"}
VALID_SEVERITIES = {"S0", "S1", "S2", "S3", "S4"}


def _truncate(detail: dict) -> dict:
    out = {}
    for k, v in (detail or {}).items():
        if isinstance(v, str) and len(v) > MAX_DETAIL_CHARS:
            out[k] = v[:MAX_DETAIL_CHARS] + f"…[+{len(v) - MAX_DETAIL_CHARS} chars]"
        elif isinstance(v, (dict, list)):
            blob = json.dumps(v, default=str)
            out[k] = (json.loads(blob) if len(blob) <= MAX_DETAIL_CHARS
                      else blob[:MAX_DETAIL_CHARS] + "…[truncated]")
        else:
            out[k] = v
    return out


def emit(
    severity: str,
    kind: str,
    title: str,
    detail: dict | None = None,
    fingerprint_key: str | None = None,
    source: str = "api",
):
    """Record an ops event, alerting if the routing rules say so.

    Returns the stored event, or `None` if anything at all went wrong.
    """
    try:
        from umbra.db.repository import Repository
        from umbra.db.schema import get_session, init_db

        if severity not in VALID_SEVERITIES:
            severity = "S2"

        # A caller that gives no stable key gets the title, which is usually
        # stable enough; ids belong in detail, not in the fingerprint.
        fp = fingerprint(kind, fingerprint_key or title)
        safe_detail = _truncate(redact(detail or {}))

        settings = get_settings()
        init_db(settings)
        session = get_session()
        try:
            repo = Repository(session, settings.raw_dir)
            event, is_new, crossed = repo.record_ops_event(
                severity=severity, kind=kind, title=title[:500],
                detail=safe_detail, fingerprint=fp, source=source,
            )
            should_alert = (
                severity in PAGING_SEVERITIES
                and (is_new or crossed)
                and not repo.ops_event_is_muted(event)
            )
            if should_alert:
                try:
                    notify(format_alert(severity=severity, kind=kind, title=title,
                                        event_id=event.id, count=event.count,
                                        detail=safe_detail))
                except Exception:  # noqa: BLE001 - the record matters more
                    logger.exception("ops alert delivery failed for %s", event.id)
            return event
        finally:
            session.close()
    except Exception:  # noqa: BLE001 - emitting must never break the caller
        logger.exception("ops.emit failed (kind=%s)", kind)
        return None
