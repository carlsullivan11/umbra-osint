"""Owned OUI lake — MAC prefix to registrant, read from the umbra-wiki corpus.

Stage S13 / M2. The data file (`imports/ieee-oui/data/oui.csv`, ~53k rows) is
produced and refreshed weekly by the umbra-wiki importer; this is the read side.
Local, offline, no API key — the same "own the data" pattern as the CT lake.

**Longest prefix wins.** IEEE carves MA-M (28-bit) and MA-S (36-bit) blocks out
of the 24-bit MA-L space, and the 24-bit parent of such a block is usually the
umbrella "IEEE Registration Authority" entry rather than the company that
actually owns the address. Measured on the live registries, 7,132 of 7,133 MA-S
and 6,420 of 6,548 MA-M prefixes resolve to a *different* vendor than their
parent — so a 24-bit-only lookup is wrong for ~13,500 prefixes while looking
perfectly plausible. Match order is 36 -> 28 -> 24, same as
`import_oui.lookup_vendor()` in umbra-wiki.
"""
from __future__ import annotations

import csv
import logging
import os
import threading
from pathlib import Path

from umbra.core.mac import normalize_mac

logger = logging.getLogger(__name__)

# Prefix lengths in hex characters, longest first. This ordering is the whole
# correctness argument — see the module docstring.
PREFIX_LENS = (9, 7, 6)

_CORPUS_RELATIVE = Path("imports") / "ieee-oui" / "data" / "oui.csv"

# IEEE registered a handful of legacy prefixes to more than one organisation
# (080030 = Network Research Corp | RMIT | CERN). The importer keeps every
# claimant joined by this separator rather than dropping any.
_CLAIMANT_SEP = "|"


def default_oui_csv() -> Path:
    """Where the OUI table lives: explicit env var, else the wiki corpus."""
    env = os.environ.get("UMBRA_OUI_CSV", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.wiki.paths import default_corpus_dir

        return default_corpus_dir() / _CORPUS_RELATIVE
    except Exception:  # noqa: BLE001 - the corpus is optional
        return Path("oui.csv")


class OuiTable:
    """Lazily loaded prefix table. Safe to construct when the file is absent."""

    def __init__(self, csv_path: Path | None = None) -> None:
        self.csv_path = Path(csv_path) if csv_path else default_oui_csv()
        self._table: dict[str, dict] | None = None
        self._lock = threading.Lock()

    # --- loading ---------------------------------------------------------

    @property
    def available(self) -> bool:
        return self.csv_path.is_file()

    @property
    def size(self) -> int:
        return len(self._load())

    def _load(self) -> dict[str, dict]:
        if self._table is not None:
            return self._table
        with self._lock:
            if self._table is not None:
                return self._table
            table: dict[str, dict] = {}
            if self.available:
                try:
                    with self.csv_path.open(newline="", encoding="utf-8") as f:
                        for row in csv.DictReader(f):
                            prefix = (row.get("prefix") or "").strip().upper()
                            if not prefix:
                                continue
                            vendor = (row.get("vendor") or "").strip()
                            table[prefix] = {
                                "prefix": prefix,
                                "bits": int(row.get("bits") or 24),
                                "registry": (row.get("registry") or "").strip(),
                                "vendor": vendor,
                                "vendors": [v.strip() for v in vendor.split(_CLAIMANT_SEP) if v.strip()],
                            }
                except (OSError, ValueError, csv.Error) as exc:
                    logger.warning("OUI table unreadable at %s: %s", self.csv_path, exc)
                    table = {}
            self._table = table
            return table

    # --- lookup ----------------------------------------------------------

    def lookup(self, mac: str) -> dict | None:
        """Most specific registration for an address or prefix, or None.

        None means "no registration found" — never a guess. A locally
        administered address has no registrant at all, and inventing one would
        be worse than saying nothing.
        """
        clean = normalize_mac(mac)
        if not clean:
            return None
        table = self._load()
        for n in PREFIX_LENS:
            if len(clean) >= n:
                hit = table.get(clean[:n])
                if hit:
                    return dict(hit)
        return None


_DEFAULT: OuiTable | None = None


def default_table() -> OuiTable:
    """Process-wide table so 53k rows are parsed once, not per collect()."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = OuiTable()
    return _DEFAULT
