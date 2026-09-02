"""Posting to X — fail-closed, capped, and off unless someone turned it on.

Every other collector in Umbra *reads*. This writes, in public, under Carl's
name, and costs money per call. So the defaults are inverted from the rest of
the codebase: nothing goes out unless four separate things are true.

    1. UMBRA_X_ENABLED=1                 — a deliberate switch, not a default
    2. all four OAuth 1.0a creds present — no partial config limping along
    3. the caller passed dry_run=False   — the CLI defaults to preview
    4. the daily cap has room            — see below

Any one missing and `post()` refuses and says which. A publishing bot that
fails *open* is how an account gets suspended and a card gets charged, so the
guard is deliberately boring and total.

**The cap is a spend limit, not a rate limit.** X charges $0.20 for a post
containing a link, and every post here contains one. `MAX_PER_DAY` exists so a
loop bug costs a few dollars instead of a few hundred.

Credentials are read from the environment and never logged, never echoed, and
never written to the store — the store keeps text, ref and cost.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

API_URL = "https://api.x.com/2/tweets"

#: Deliberately low. Ten link-posts a day is ~$60/month, and an OSINT feed that
#: posts more than a few times a day reads as noise regardless of policy.
MAX_PER_DAY = 6

_CRED_ENV = (
    "UMBRA_X_API_KEY",
    "UMBRA_X_API_SECRET",
    "UMBRA_X_ACCESS_TOKEN",
    "UMBRA_X_ACCESS_SECRET",
)


class NotEnabled(RuntimeError):
    """Posting was attempted while some part of the gate was shut."""


@dataclass
class PostResult:
    ok: bool
    remote_id: str | None
    detail: str


def enabled() -> bool:
    return (os.environ.get("UMBRA_X_ENABLED") or "").strip() == "1"


def missing_credentials() -> list[str]:
    return [name for name in _CRED_ENV if not (os.environ.get(name) or "").strip()]


def preflight(store, *, dry_run: bool) -> str | None:
    """Why this must not post right now, or None if it may.

    Checked before composing anything so a refusal is cheap and explicit.
    """
    if dry_run:
        return None
    if not enabled():
        return ("UMBRA_X_ENABLED is not 1 — posting is off. This is the switch, "
                "not an error.")
    missing = missing_credentials()
    if missing:
        return f"missing credential(s): {', '.join(missing)}"
    used = store.posted_today()
    if used >= MAX_PER_DAY:
        return (f"daily cap reached ({used}/{MAX_PER_DAY}). At $0.20 per "
                f"link-post the cap is a spend limit, not a rate limit.")
    return None


def post(text: str, *, store, dry_run: bool = True) -> PostResult:
    """One post. Refuses unless every gate is open."""
    blocked = preflight(store, dry_run=dry_run)
    if blocked:
        raise NotEnabled(blocked)
    if dry_run:
        return PostResult(True, None, "dry run — nothing was sent")

    try:
        from requests_oauthlib import OAuth1Session
    except ImportError:  # pragma: no cover - optional dependency
        raise NotEnabled(
            "requests_oauthlib is not installed; `pip install umbra-osint[social]`"
        ) from None

    session = OAuth1Session(
        os.environ["UMBRA_X_API_KEY"],
        client_secret=os.environ["UMBRA_X_API_SECRET"],
        resource_owner_key=os.environ["UMBRA_X_ACCESS_TOKEN"],
        resource_owner_secret=os.environ["UMBRA_X_ACCESS_SECRET"],
    )
    resp = session.post(API_URL, json={"text": text}, timeout=30)
    if resp.status_code >= 400:
        # Never log the body of a failed auth call; it can echo the request.
        return PostResult(False, None, f"X API returned {resp.status_code}")
    remote_id = ((resp.json() or {}).get("data") or {}).get("id")
    return PostResult(True, str(remote_id) if remote_id else None, "posted")
