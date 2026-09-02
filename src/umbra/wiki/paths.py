"""Paths for wiki corpus and FTS index."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    raw = os.environ.get("UMBRA_DATA_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".umbra").resolve()


def default_corpus_dir() -> Path:
    """Resolve corpus directory (first hit wins)."""
    env = os.environ.get("UMBRA_WIKI_PATH", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    candidates = [
        data_dir() / "wiki",
        Path(__file__).resolve().parents[4] / "umbra-wiki",  # ~/umbra/src/umbra/wiki -> rarely
        Path.home() / "umbra-wiki",
    ]
    # Also sibling of package checkout: .../umbra/../umbra-wiki
    try:
        pkg_root = Path(__file__).resolve().parents[3]  # .../umbra (repo root when editable)
        candidates.insert(1, pkg_root.parent / "umbra-wiki")
        candidates.insert(1, pkg_root / "umbra-wiki")
    except IndexError:
        pass
    for c in candidates:
        if (c / "curated").is_dir() or (c / "imports").is_dir():
            return c.resolve()
    return (data_dir() / "wiki").resolve()


def default_index_path() -> Path:
    env = os.environ.get("UMBRA_WIKI_INDEX", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return data_dir() / "wiki-index.sqlite"
