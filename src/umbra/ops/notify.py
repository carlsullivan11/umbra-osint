"""Alert delivery + the rules about what may leave the box.

Telegram is the same bot the health watcher and deploy poller already use. The
helper lives here rather than being copy-pasted a third time; the deploy scripts
keep their own copies because they run on the host, outside the package.
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# Substring match, case-insensitive. Event detail is assembled from real cases
# and shipped to Telegram, so this errs toward over-redacting: a redacted field
# costs a moment of triage, a leaked one is a credential in a chat log.
_SECRET_HINTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "cookie", "session", "credential", "private_key",
)
_REDACTED = "[redacted]"


def _is_secret(key: str) -> bool:
    k = (key or "").lower()
    return any(hint in k for hint in _SECRET_HINTS)


def redact(value, _depth: int = 0):
    """Strip secret-shaped fields from nested detail before it is stored."""
    if _depth > 8:
        return value
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _is_secret(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    return value


_SEVERITY_ICON = {"S0": "🔴", "S1": "🟠", "S2": "🟡", "S3": "🔵", "S4": "⚪"}


def format_alert(severity: str, kind: str, title: str, event_id: str,
                 count: int, detail: dict | None = None) -> str:
    """One screen of Telegram: what broke, how often, and how to triage it."""
    icon = _SEVERITY_ICON.get(severity, "⚪")
    lines = [f"{icon} Umbra {severity} {kind}", title[:300]]
    safe = redact(detail or {})
    for key in ("case_id", "job_id", "collector", "path", "worker_id"):
        if safe.get(key):
            lines.append(f"{key}={safe[key]}")
    if count > 1:
        lines.append(f"count={count}")
    lines.append(f"event {event_id}")
    lines.append(f"triage: umbra ops show {event_id}")
    return "\n".join(lines)


def notify(text: str, timeout: float = 10.0) -> bool:
    """Send to Telegram. Returns False rather than raising — alerting is never
    allowed to be the thing that breaks."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        logger.info("telegram not configured; alert dropped: %s", text.splitlines()[0])
        return False
    try:
        import httpx

        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=timeout,
        )
        return True
    except Exception:  # noqa: BLE001
        logger.exception("failed to send ops alert")
        return False


def fingerprint(kind: str, key: str) -> str:
    """Stable dedupe key. Callers pass a *stable* key — collector name and
    exception type, never a job or case id, or one broken collector becomes a
    hundred separate events."""
    import hashlib

    norm = re.sub(r"\s+", " ", (key or "").strip().lower())
    return hashlib.sha256(f"{kind}|{norm}".encode("utf-8")).hexdigest()[:32]
