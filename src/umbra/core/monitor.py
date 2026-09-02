"""Watchlist monitoring — snapshot + diff.

Watches were operator-only for most of the project's life: created from the CLI,
on the operator's own machine, against hosts they chose. The web UI changes what
this module is. A visitor who can name a host, and have the server fetch it on a
timer, has a server-side request forgery primitive — so the HTTP snapshot goes
through `umbra.core.http_guard.GuardedClient` like every other piece of
collector egress. The guard was written during the security review and this path
was missed only because nothing public could reach it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import dns.resolver

from umbra.core.config import Settings
from umbra.core.dns import get_resolver
from umbra.core.http_guard import GuardedClient
from umbra.db.repository import Repository


def _dns_snapshot(domain: str) -> dict[str, Any]:
    resolver = get_resolver()
    resolver.lifetime = 5.0
    out: dict[str, Any] = {"domain": domain, "a": [], "mx": [], "ns": [], "txt": []}
    for rtype, key in (("A", "a"), ("AAAA", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")):
        try:
            ans = resolver.resolve(domain, rtype)
            vals = sorted({rr.to_text().strip('"') for rr in ans})
            if rtype == "AAAA":
                out["a"] = sorted(set(out["a"]) | set(vals))
            else:
                out[key] = vals
        except Exception:
            pass
    return out


def _http_snapshot(domain: str, ua: str, timeout: float) -> dict[str, Any]:
    """One HTTPS fetch, SSRF-checked.

    `GuardedClient` resolves the host and refuses private, loopback and
    link-local targets, and re-checks every redirect hop — a public 302 to
    169.254.169.254 is the same attack with one more step.
    """
    url = f"https://{domain}/"
    try:
        with GuardedClient(timeout=timeout, headers={"User-Agent": ua},
                           follow_redirects=True) as client:
            r = client.get(url)
            body = r.content[:20000]
            return {
                "url": str(r.url),
                "status": r.status_code,
                "title_hash": hashlib.sha256(body).hexdigest()[:16],
                "server": r.headers.get("server"),
                "len": len(r.content),
            }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _hibp_snapshot(email: str, api_key: str | None, ua: str, timeout: float) -> dict[str, Any]:
    if not api_key:
        return {"skipped": True, "reason": "no_hibp_key"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": ua, "Accept": "application/json"}
    try:
        with GuardedClient(timeout=timeout, headers=headers) as client:
            r = client.get(url, params={"truncateResponse": "true"})
            if r.status_code == 404:
                return {"breached": False, "names": []}
            if r.status_code != 200:
                return {"error": f"http_{r.status_code}"}
            names = sorted({b.get("Name") for b in r.json() if b.get("Name")})
            return {"breached": bool(names), "names": names, "count": len(names)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    if not old:
        return {"first_seen": True, "changes": []}
    changes: list[dict[str, Any]] = []

    def _cmp(path: str, a: Any, b: Any) -> None:
        if a == b:
            return
        if isinstance(a, list) and isinstance(b, list):
            sa, sb = set(map(str, a)), set(map(str, b))
            added, removed = sorted(sb - sa), sorted(sa - sb)
            if added or removed:
                changes.append({"path": path, "added": added, "removed": removed})
        else:
            changes.append({"path": path, "from": a, "to": b})

    # shallow + one-level keys of interest
    keys = set(old) | set(new)
    for k in sorted(keys):
        if k in {"error"} and new.get(k):
            changes.append({"path": k, "to": new.get(k)})
            continue
        _cmp(k, old.get(k), new.get(k))
    return {"first_seen": False, "changed": bool(changes), "changes": changes}


def check_watch_item(repo: Repository, settings: Settings, watch_id: str) -> dict[str, Any]:
    item = repo.get_watch(watch_id)
    if not item or not item.enabled:
        raise ValueError("watch missing or disabled")

    t, v = item.entity_type, item.value
    if t == "domain":
        snap = {
            "kind": "domain",
            "dns": _dns_snapshot(v),
            "http": _http_snapshot(v, settings.user_agent, settings.request_timeout_s),
        }
    elif t == "email":
        snap = {
            "kind": "email",
            "hibp": _hibp_snapshot(
                v,
                settings.hibp_api_key,
                settings.hibp_user_agent,
                settings.request_timeout_s,
            ),
        }
    else:
        snap = {"kind": t, "value": v, "note": "unsupported watch type for auto-check"}

    old = item.last_snapshot or {}
    diff = diff_snapshots(old, snap)
    repo.update_watch_snapshot(watch_id, snap, diff)
    repo.audit(
        item.case_id,
        "watch.check",
        {"watch_id": watch_id, "changed": diff.get("changed"), "type": t, "value": v},
    )
    # commit audit
    repo.session.commit()
    return {"watch_id": watch_id, "type": t, "value": v, "diff": diff, "snapshot": snap}


def check_all_watches(repo: Repository, settings: Settings) -> list[dict[str, Any]]:
    results = []
    for item in repo.list_watch(enabled_only=True):
        try:
            results.append(check_watch_item(repo, settings, item.id))
        except Exception as exc:  # noqa: BLE001
            results.append({"watch_id": item.id, "error": str(exc)})
    return results


def render_monitor_report(results: list[dict[str, Any]]) -> str:
    lines = ["# Watchlist monitor report", ""]
    changed_n = sum(1 for r in results if (r.get("diff") or {}).get("changed"))
    lines.append(f"Checked **{len(results)}** item(s); **{changed_n}** with changes.")
    lines.append("")
    for r in results:
        if r.get("error"):
            lines.append(f"- `{r.get('watch_id')}` ERROR: {r['error']}")
            continue
        diff = r.get("diff") or {}
        flag = "CHANGED" if diff.get("changed") else ("NEW" if diff.get("first_seen") else "ok")
        lines.append(f"## [{flag}] {r.get('type')}: `{r.get('value')}`")
        if diff.get("first_seen"):
            lines.append("- First snapshot recorded.")
        for c in diff.get("changes") or []:
            lines.append(f"- `{c}`")
        lines.append("")
    return "\n".join(lines)
