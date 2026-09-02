from __future__ import annotations

from umbra.collectors.username_presence import _exists_heuristic
from umbra.collectors.hibp_breach import remediation_for_data_classes


def test_soft404_hn():
    ok, _ = _exists_heuristic("hackernews", 200, "No such user.", "https://news.ycombinator.com/user?id=x")
    assert ok is False


def test_soft404_github_ok():
    ok, conf = _exists_heuristic(
        "github",
        200,
        "<html>followers repositories</html>",
        "https://github.com/octocat",
    )
    assert ok is True
    assert conf >= 0.7


def test_remediation_still_ok():
    assert remediation_for_data_classes(["Passwords"])
