"""Umbra — graph-first local OSINT platform."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Read from installed package metadata rather than repeating the number here.
# Four surfaces used to answer this question three different ways: pyproject
# said 0.2.0, this file said 0.1.0, the FastAPI app hardcoded "0.2.0", and the
# CLI had no --version flag at all. A user comparing `pip show` against
# /health could reasonably conclude they were running something they were not.
#
# pyproject.toml is the single source of truth. The fallback is for running
# from a source tree that was never installed.
try:
    __version__ = _pkg_version("umbra-osint")
except PackageNotFoundError:  # pragma: no cover - source checkout, not installed
    __version__ = "0.0.0+source"

__all__ = ["__version__"]
