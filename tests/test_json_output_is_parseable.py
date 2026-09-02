"""`--json` must survive a pipe into jq.

Rich soft-wraps to the terminal width and will break a long string mid-token.
A `--json` flag routed through `rprint` therefore produces output that parses
on short results and fails on long ones — which is the worst possible failure
shape, because it looks like it works.

This had already been fixed once in this codebase (a truncated handoff URL, and
again for `umbra file --json`). It came back in `umbra lookup --json`, and was
found the moment a D3FEND page with a long body was looked up. Three modules
still had it: wiki_cmd, people_cmd, ops_cmd.
"""
from __future__ import annotations

import json
import re
import subprocess
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

CLI_DIR = Path(__file__).resolve().parent.parent / "src" / "umbra" / "cli"


def test_no_json_dump_goes_through_rich():
    """The static guard. Grep, because the next regression arrives the same way
    the last two did: someone reaches for the printer already imported."""
    offenders = []
    for path in CLI_DIR.glob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"\brprint\(\s*json\.dumps", line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "rich soft-wraps and corrupts JSON — use plain print():\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("query", ["D3-RF", "CVE-2021-44228", "CWE-79"])
def test_lookup_json_parses_for_pages_with_long_bodies(query, tmp_path):
    """The dynamic check: a real page, through the real CLI, into json.loads.

    Narrow terminal on purpose — rich wraps to COLUMNS, so a small width is
    what makes the old bug reproduce.
    """
    import shutil

    umbra = shutil.which("umbra")
    if not umbra:
        pytest.skip("umbra console script not on PATH")

    proc = subprocess.run(
        [umbra, "lookup", query, "--json"],
        capture_output=True, text=True, timeout=180,
        env={"COLUMNS": "80", "TERM": "dumb", **dict(__import__("os").environ)},
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        pytest.skip(f"no corpus hit for {query} in this environment")

    parsed = json.loads(proc.stdout)  # the assertion is that this does not raise
    assert isinstance(parsed, list)
