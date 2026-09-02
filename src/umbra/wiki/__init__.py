"""Umbra wiki engine — local corpus index + lookup (MIT)."""

from __future__ import annotations

from umbra.wiki.paths import default_corpus_dir, default_index_path
from umbra.wiki.service import WikiService

__all__ = ["WikiService", "default_corpus_dir", "default_index_path"]
