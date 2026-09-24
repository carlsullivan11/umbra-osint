"""Turn what an analyst pastes into alerts with external indicators.

Three shapes are accepted:

- one indicator (`185.220.101.1`, `evil.example`, `http://1.2.3.4/x.sh`)
- a JSON alert, or a list/NDJSON of them, in common SIEM field names
  (Elastic ECS, Suricata EVE, Wazuh, Zeek, or flat `src_ip`/`dst_ip`)
- plain text: an IOC list or a pasted log line, run through the same
  deterministic extractor as `umbra file`

**What leaves the machine is decided here.** Only public addresses, domains and
URLs become indicators. Internal addresses, host names, user names, command
lines and file paths are never copied onto an `Alert`; the fields that were
present are listed in `kept_local` so the card can say so (docs/JEV.md §5).
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from umbra.core.http_guard import is_public_ip
from umbra.core.models import EntityType

#: Most alerts one command will take. A SIEM export can be enormous; this is a
#: triage tool, not a bulk importer.
MAX_ALERTS = 50

KINDS = ("outbound_conn", "dns_query", "web_request", "inbound_conn", "indicator")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# First match wins. Keys are matched after flattening nested objects to dots
# and lower-casing.
_DEST_IP = ("destination.ip", "dest_ip", "dst_ip", "dstip", "data.dstip", "destination_ip",
            "dest.ip", "ip.dst", "id.resp_h", "remote_ip", "remote.ip")
_SRC_IP = ("source.ip", "src_ip", "srcip", "data.srcip", "source_ip", "src.ip", "ip.src",
           "id.orig_h", "client.ip")
_DEST_PORT = ("destination.port", "dest_port", "dst_port", "dstport", "data.dstport",
              "id.resp_p", "remote_port")
_DOMAIN = ("dns.question.name", "dns.rrname", "rrname", "dns.query", "query",
           "destination.domain", "url.domain", "http.hostname", "tls.sni",
           "tls.server_name", "server_name", "domain")
_URL = ("url.full", "url.original", "http.url", "url", "request_url")
_USER_AGENT = ("user_agent.original", "http.http_user_agent", "http.user_agent",
               "user_agent", "useragent", "http_user_agent")
_PATH = ("url.path", "http.uri", "uri", "request_path", "path")
_RULE = ("rule.name", "alert.signature", "signature", "rule.description", "rule_name",
         "alert_name", "event.action")
_DIRECTION = ("network.direction", "direction", "flow.direction")
_COUNT = ("event.count", "count", "occurrences", "hits")
_SUBJECT = ("email.subject", "subject")

#: Fields that identify our side of the alert. Their presence is reported;
#: their values are never read into an Alert.
_LOCAL_ONLY = ("host.name", "hostname", "host.hostname", "user.name", "user", "username",
               "process.command_line", "process.executable", "file.path", "agent.name",
               "observer.name", "source.user.name", "destination.user.name")


@dataclass
class Indicator:
    type: EntityType
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type.value, "value": self.value}


@dataclass
class Alert:
    kind: str
    indicators: list[Indicator] = field(default_factory=list)
    #: facts the analyst's own tooling established (rule name, port, count)
    context: dict[str, str] = field(default_factory=dict)
    #: text the far side controls (user agent, request path, subject)
    untrusted: dict[str, str] = field(default_factory=dict)
    #: fields that were present but never leave the machine
    kept_local: list[str] = field(default_factory=list)
    events: int | None = None
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "label": self.label,
                "indicators": [i.to_dict() for i in self.indicators],
                "context": dict(self.context), "untrusted": dict(self.untrusted),
                "kept_local": list(self.kept_local), "events": self.events}


# --- single values --------------------------------------------------------------


def _public_ip(value: Any) -> str | None:
    try:
        ip = str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None
    return ip if is_public_ip(ip) else None


def _private_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False
    return not is_public_ip(str(value).strip().strip("[]"))


def _domain(value: Any) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d) or d.endswith((".local", ".internal", ".lan", ".corp", ".home.arpa")):
        return None
    return d


def _url(value: Any) -> str | None:
    raw = str(value or "").strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname
    if _public_ip(host) is None and _domain(host) is None:
        return None
    return raw


def classify_indicator(token: str) -> Indicator | None:
    """One pasted token -> an external indicator, or None."""
    if ip := _public_ip(token):
        return Indicator(EntityType.IP, ip)
    if url := _url(token):
        return Indicator(EntityType.URL, url)
    if dom := _domain(token):
        return Indicator(EntityType.DOMAIN, dom)
    return None


def with_url_hosts(indicators: list[Indicator]) -> list[Indicator]:
    """Add each URL's host as its own indicator.

    Blocklists and the abuse lakes key on hosts, not full URLs, so without this a
    URL's listing is never checked.
    """
    out = list(indicators)
    have = {(i.type, i.value) for i in out}
    for ind in indicators:
        if ind.type is not EntityType.URL:
            continue
        host = classify_indicator(urlsplit(ind.value).hostname or "")
        if host is not None and (host.type, host.value) not in have:
            out.append(host)
            have.add((host.type, host.value))
    return out


# --- JSON alerts ------------------------------------------------------------------


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}".lower() if prefix else str(k).lower()
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            else:
                out[key] = v
    return out


def _first(flat: dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        v = flat.get(k)
        if v not in (None, "", [], {}):
            return v[0] if isinstance(v, list) else v
    return None


def _as_int(v: Any) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def alert_from_json(obj: dict[str, Any]) -> Alert:
    flat = _flatten(obj)
    dest_raw, src_raw = _first(flat, _DEST_IP), _first(flat, _SRC_IP)
    dest_ip, src_ip = _public_ip(dest_raw), _public_ip(src_raw)
    domain = _domain(_first(flat, _DOMAIN))
    url_val = _first(flat, _URL)
    url = _url(url_val)
    direction = str(_first(flat, _DIRECTION) or "").lower()
    inbound = direction in ("inbound", "ingress", "in", "incoming") or (
        src_ip is not None and dest_raw is not None and _private_ip(dest_raw))

    alert = Alert(kind="outbound_conn")
    if inbound and src_ip:
        # Somebody reached us. The host name and URL in the alert are *ours*;
        # the only external indicator is who connected.
        alert.kind = "inbound_conn"
        domain = url = None
    elif domain and _first(flat, ("dns.question.name", "dns.rrname", "rrname", "dns.query", "query")):
        alert.kind = "dns_query"
    elif url or (domain and _first(flat, _USER_AGENT)):
        alert.kind = "web_request"

    remote_ip = src_ip if alert.kind == "inbound_conn" else dest_ip
    if url:
        alert.indicators.append(Indicator(EntityType.URL, url))
    if domain and not (url and urlsplit(url).hostname == domain):
        alert.indicators.append(Indicator(EntityType.DOMAIN, domain))
    if remote_ip:
        alert.indicators.append(Indicator(EntityType.IP, remote_ip))
    alert.indicators = with_url_hosts(alert.indicators)

    port = _as_int(_first(flat, _DEST_PORT))
    if port is not None and alert.kind in ("outbound_conn", "inbound_conn"):
        alert.context["remote port" if alert.kind == "outbound_conn" else "our port"] = str(port)
    if rule := _first(flat, _RULE):
        alert.context["detection rule"] = str(rule)[:200]
    alert.events = _as_int(_first(flat, _COUNT))

    if ua := _first(flat, _USER_AGENT):
        alert.untrusted["user agent"] = str(ua)
    path = _first(flat, _PATH)
    if path is None and isinstance(url_val, str) and url_val.startswith("/"):
        path = url_val
    if path and alert.kind in ("inbound_conn", "web_request"):
        alert.untrusted["requested path"] = str(path)
    if subj := _first(flat, _SUBJECT):
        alert.untrusted["subject"] = str(subj)

    alert.kept_local = sorted(k for k in _LOCAL_ONLY if flat.get(k) not in (None, ""))
    for raw in (dest_raw, src_raw):
        if raw is not None and _private_ip(raw):
            alert.kept_local.append("internal address")
            break
    first = alert.indicators[0].value if alert.indicators else "(no external indicator)"
    alert.label = f"{alert.kind}: {first}"
    return alert


# --- dispatch -------------------------------------------------------------------


def _json_objects(text: str) -> list[dict[str, Any]] | None:
    s = text.strip()
    if not s or s[0] not in "[{":
        return None
    try:
        data = json.loads(s)
    except ValueError:
        # NDJSON: one alert per line
        objs = []
        for line in s.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except ValueError:
                return None
        data = objs
    if isinstance(data, dict):
        # a SIEM search response wraps hits
        hits = (data.get("hits") or {}).get("hits") if isinstance(data.get("hits"), dict) else None
        data = [h.get("_source", h) for h in hits] if isinstance(hits, list) else [data]
    if not isinstance(data, list):
        return None
    return [d for d in data if isinstance(d, dict)]


def _from_text(text: str) -> list[Alert]:
    from umbra.intent.extract import extract_hits, hits_to_seeds

    seen: set[tuple[str, str]] = set()
    alerts: list[Alert] = []
    for seed in hits_to_seeds(extract_hits(text)):
        if seed.type not in (EntityType.IP, EntityType.DOMAIN, EntityType.URL):
            continue
        ind = classify_indicator(seed.value)
        if ind is None or (ind.type.value, ind.value) in seen:
            continue
        seen.add((ind.type.value, ind.value))
        alerts.append(Alert(kind="indicator", indicators=with_url_hosts([ind]), label=ind.value))
    return alerts


def parse_input(text: str) -> tuple[list[Alert], list[str]]:
    """Alerts to triage, plus notes about anything skipped or capped."""
    notes: list[str] = []
    stripped = text.strip()
    if not stripped:
        return [], ["nothing to triage"]
    objs = _json_objects(stripped)
    if objs is not None:
        alerts = [alert_from_json(o) for o in objs]
    elif len(stripped.split()) == 1 and (ind := classify_indicator(stripped)):
        alerts = [Alert(kind="indicator", indicators=with_url_hosts([ind]), label=ind.value)]
    else:
        alerts = _from_text(stripped)
    if len(alerts) > MAX_ALERTS:
        notes.append(f"only the first {MAX_ALERTS} of {len(alerts)} alerts were triaged")
        alerts = alerts[:MAX_ALERTS]
    empty = sum(1 for a in alerts if not a.indicators)
    if empty:
        notes.append(f"{empty} alert(s) had no public address, domain or URL to assess")
    return alerts, notes
