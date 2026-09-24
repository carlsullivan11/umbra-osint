"""A source that refused to answer has not found anything.

`opencorporates` produced 31 evidence rows on production and every single one
said `OpenCorporates captcha wall or block — not scraped` at confidence 0.30. It
has never once returned data: OpenCorporates serves an hCaptcha wall to
datacenter IPs, and the VPS is a datacenter IP.

Those rows sat in the results list beside real findings, in every person and org
search, saying nothing. The collector already appended a *note* saying the same
thing — the evidence row was a duplicate of it in the wrong column.

This is the U2 distinction: results, misconfiguration and source failure are
three different things. A block is the third. It belongs in notes, where the
run-notes UI explains it, and nowhere near the evidence list.

The collector itself stays. It fails from a datacenter and works from a
residential CLI, and the fix for "this source is blocked here" is to say so, not
to pretend the source does not exist.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.collectors.opencorporates import OpenCorporatesCollector

CAPTCHA_HTML = "<html><body>Please complete the hcaptcha challenge</body></html>"
BLOCK_HTML = "<html><body>HAProxy Challenge</body></html>"


class _Resp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status


class _Http:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp

    def get(self, *_a, **_kw) -> _Resp:
        return self._resp


def _run(html: str, status: int = 200):
    entity = SimpleNamespace(value="Acme Ltd", norm_key="org:acme ltd")
    ctx = SimpleNamespace(http=_Http(_Resp(html, status)), settings=None)
    return OpenCorporatesCollector().collect(entity, ctx)


@pytest.mark.parametrize("html,status", [
    (CAPTCHA_HTML, 200),
    (BLOCK_HTML, 200),
    ("<html>whatever</html>", 403),
])
def test_a_blocked_fetch_writes_no_evidence(html, status):
    assert _run(html, status).evidence == []


@pytest.mark.parametrize("html,status", [
    (CAPTCHA_HTML, 200),
    (BLOCK_HTML, 200),
    ("<html>whatever</html>", 403),
])
def test_a_blocked_fetch_still_says_so_in_notes(html, status):
    notes = " ".join(_run(html, status).notes).lower()
    assert notes, "a blocked source must not fail silently"
    assert "opencorporates" in notes


def test_the_note_names_it_as_unchecked_not_as_absence():
    """The whole point: no result here is not 'no company by that name'."""
    notes = " ".join(_run(CAPTCHA_HTML).notes).lower()
    assert "unchecked" in notes or "not checked" in notes


def test_a_transport_error_also_writes_no_evidence():
    class _Boom:
        def get(self, *_a, **_kw):
            raise RuntimeError("connection reset")

    entity = SimpleNamespace(value="Acme Ltd", norm_key="org:acme ltd")
    ctx = SimpleNamespace(http=_Boom(), settings=None)
    res = OpenCorporatesCollector().collect(entity, ctx)
    assert res.evidence == []
    assert res.notes
