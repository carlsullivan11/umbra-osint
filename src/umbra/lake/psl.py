"""The Public Suffix List — where one organisation's namespace ends.

`umbra.email.parse.org_domain` decides whether two hostnames belong to the same
organisation, and DMARC alignment is defined in exactly those terms. It was
doing it with 25 hardcoded multi-label suffixes and a comment admitting as much.

The cost was measurable, and it ran the wrong way for a security tool:

    attacker.github.io      vs victim.github.io       → both "github.io"
    evil.herokuapp.com      vs bank.herokuapp.com     → both "herokuapp.com"
    evil.s3.amazonaws.com   vs corp.s3.amazonaws.com  → both "amazonaws.com"

Every one of those is a **false alignment**. A DKIM signature from one tenant of
a shared host "aligns" with a From: address on another, and the verdict reports
the message as authenticated when it is not. That is a false negative in
spoofing detection, which is the failure direction that matters.

The list has two halves and they mean different things:

- **ICANN** — real registry suffixes (`co.uk`, `com.au`).
- **PRIVATE** — namespaces a company hands to third parties (`github.io`,
  `herokuapp.com`, `blob.core.windows.net`). This half is what the hardcoded set
  missed entirely, and it is where shared-hosting spoofing lives.

Both count for alignment: two tenants of `github.io` are no more the same
organisation than two registrants under `co.uk`.

Source: https://publicsuffix.org/list/public_suffix_list.dat (Mozilla, MPL-2.0).
~333 KB, so it is stored as-is rather than in a database — parsing it is a few
milliseconds and the file is the authoritative artifact.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
ATTRIBUTION = "Public Suffix List by Mozilla (https://publicsuffix.org) — MPL-2.0"

_ICANN_START = "// ===BEGIN ICANN DOMAINS==="
_PRIVATE_START = "// ===BEGIN PRIVATE DOMAINS==="


def default_psl_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "public_suffix_list.dat"


def parse(text: str) -> tuple[set[str], set[str], set[str]]:
    """(rules, wildcards, exceptions) from the list's own format.

    Three rule shapes, and conflating them gets answers wrong:
      `co.uk`      an ordinary suffix
      `*.ck`       every label under .ck is a suffix
      `!www.ck`    …except this one, which is registrable
    """
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:].lower())
        elif line.startswith("*."):
            wildcards.add(line[2:].lower())
        else:
            rules.add(line.lower())
    return rules, wildcards, exceptions


class PublicSuffixList:
    """Longest-match lookup over the list, loaded lazily and cached."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_psl_path()
        self._lock = threading.Lock()
        self._rules: set[str] | None = None
        self._wildcards: set[str] = set()
        self._exceptions: set[str] = set()

    @classmethod
    def from_settings(cls, settings) -> "PublicSuffixList":
        return cls(default_psl_path(getattr(settings, "data_dir", None)))

    @property
    def available(self) -> bool:
        return self.path.is_file()

    def _ensure(self) -> bool:
        if self._rules is not None:
            return bool(self._rules)
        with self._lock:
            if self._rules is not None:
                return bool(self._rules)
            if not self.path.is_file():
                self._rules = set()
                return False
            try:
                text = self.path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._rules = set()
                return False
            self._rules, self._wildcards, self._exceptions = parse(text)
            return bool(self._rules)

    def public_suffix(self, host: str) -> str | None:
        """The public suffix of `host`, or None when the list is unavailable."""
        if not self._ensure():
            return None
        labels = host.strip().lower().rstrip(".").split(".")
        if len(labels) < 2:
            return None

        # Exceptions win outright: `!www.ck` makes www.ck registrable even
        # though `*.ck` would otherwise swallow it.
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                return ".".join(labels[i + 1:]) or None

        best: str | None = None
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self._rules:
                best = candidate
                break
            parent = ".".join(labels[i + 1:])
            if parent and parent in self._wildcards:
                best = candidate
                break
        return best

    def registrable(self, host: str) -> str | None:
        """eTLD+1 — the organisation boundary. None when unknown.

        None, not a guess: returning the last two labels when the list is not
        loaded is exactly the behaviour that produced the false alignments, and
        the caller needs to know it is falling back.
        """
        suffix = self.public_suffix(host)
        if suffix is None:
            return None
        labels = host.strip().lower().rstrip(".").split(".")
        suffix_labels = suffix.split(".")
        if len(labels) <= len(suffix_labels):
            # The host *is* a public suffix — `github.io` itself is nobody's
            # registrable domain.
            return None
        return ".".join(labels[-(len(suffix_labels) + 1):])

    def status(self) -> dict[str, Any]:
        loaded = self._ensure()
        stamp = None
        if self.path.is_file():
            stamp = datetime.fromtimestamp(
                self.path.stat().st_mtime, tz=timezone.utc
            ).isoformat()
        return {
            "path": str(self.path),
            "available": self.available,
            "rules": len(self._rules or ()),
            "wildcards": len(self._wildcards),
            "exceptions": len(self._exceptions),
            "loaded": loaded,
            "updated_at": stamp,
            "attribution": ATTRIBUTION,
        }


def sync(psl: PublicSuffixList, http, *, url: str = PSL_URL, timeout: float = 60.0) -> dict:
    """Fetch and replace the list. Written via a temp file, then moved."""
    resp = http.get(url, timeout=timeout, follow_redirects=True)
    resp.raise_for_status()
    text = resp.text
    rules, wildcards, exceptions = parse(text)
    if len(rules) < 1000:
        # The real list carries thousands. A short parse means a captive portal
        # or an error page, and overwriting a good list with it would silently
        # restore the false-alignment behaviour.
        raise ValueError(
            f"public suffix list from {url} parsed to only {len(rules)} rules — "
            "refusing to replace the existing list"
        )

    psl.path.parent.mkdir(parents=True, exist_ok=True)
    tmp = psl.path.with_suffix(psl.path.suffix + ".importing")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(psl.path)
    psl._rules = None  # force reload
    return {
        "rules": len(rules),
        "wildcards": len(wildcards),
        "exceptions": len(exceptions),
        "path": str(psl.path),
        "url": url,
    }
