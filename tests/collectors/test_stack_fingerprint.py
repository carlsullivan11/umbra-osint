"""Server stack fingerprint from connections Umbra already makes.

`tls_cert` already completes one TLS handshake and `http_probe` already makes
one HTTP GET, on an authorized lookup. Both discarded everything about *how*
the peer answered — TLS version, cipher, ALPN, the order the server listed its
headers in. Those are facts about the connection we already paid for, so
recording them costs no new request, no new port, and no new collector.

**A fingerprint is not an identity.** Every site behind Cloudflare looks like
Cloudflare, because for the purposes of a TLS handshake it *is* Cloudflare.
Shared hosting collides the same way. Header order is the weakest signal of the
lot and is capped at 0.4 confidence accordingly.

**A miss is unchecked, not clean.** No handshake means no `fp_*` props, not
`fp_tls_version = None` rendered as a finding.

No live network here: the socket and the SSL context are both faked.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from umbra.collectors.tls_cert import TlsCertCollector
from umbra.core.models import EntityType

CTX = SimpleNamespace(
    settings=SimpleNamespace(request_timeout_s=10.0), case_id="c", run_id="r", http=None
)


def domain(value: str = "example.com"):
    return SimpleNamespace(
        type=EntityType.DOMAIN.value, value=value, confidence=1.0,
        norm_key=f"domain:{value}", is_seed=True, props={},
    )


class _FakeSSock:
    """Just enough of ssl.SSLSocket for the three calls the collector makes."""

    def __init__(self, *, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                 alpn="h2", der=b"fake-der-bytes", cert=None):
        self._version, self._cipher, self._alpn = version, cipher, alpn
        self._der, self._cert = der, cert or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def version(self):
        return self._version

    def cipher(self):
        return self._cipher

    def selected_alpn_protocol(self):
        return self._alpn

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else self._cert


class _FakeCtx:
    def __init__(self, ssock):
        self._ssock = ssock
        self.alpn_offered = None
        self.check_hostname = True
        self.verify_mode = None

    def set_alpn_protocols(self, protocols):
        self.alpn_offered = list(protocols)

    def wrap_socket(self, sock, server_hostname=None):
        return self._ssock


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def handshake(monkeypatch):
    """Install a fake handshake; returns the fake context for assertions."""
    state = {}

    def install(**kw):
        ssock = _FakeSSock(**kw)
        ctx = _FakeCtx(ssock)
        monkeypatch.setattr("umbra.collectors.tls_cert.socket.create_connection",
                            lambda *a, **k: _FakeConn())
        monkeypatch.setattr("umbra.collectors.tls_cert.ssl.create_default_context",
                            lambda *a, **k: ctx)
        state["ctx"] = ctx
        return ctx

    install.state = state  # type: ignore[attr-defined]
    return install


def props_for(result, kind: EntityType, value: str | None = None) -> dict:
    for ent in result.entities:
        if ent.type == kind and (value is None or ent.value == value):
            if ent.props:
                return ent.props
    return {}


# --- TLS facts land on both the domain and the cert ------------------------

def test_tls_version_cipher_and_alpn_are_recorded(handshake):
    handshake()
    result = TlsCertCollector().collect(domain(), CTX)

    dom = props_for(result, EntityType.DOMAIN, "example.com")
    assert dom["fp_tls_version"] == "TLSv1.3"
    assert dom["fp_tls_cipher"] == "TLS_AES_256_GCM_SHA384"
    assert dom["fp_alpn"] == "h2"
    assert dom["fp_http2"] is True


def test_the_cert_entity_carries_the_same_facts(handshake):
    handshake()
    result = TlsCertCollector().collect(domain(), CTX)
    cert = props_for(result, EntityType.CERT)
    assert cert["fp_tls_version"] == "TLSv1.3"
    assert cert["fp_tls_cipher"] == "TLS_AES_256_GCM_SHA384"
    assert cert["fp_alpn"] == "h2"


def test_http11_is_not_http2(handshake):
    handshake(alpn="http/1.1")
    dom = props_for(TlsCertCollector().collect(domain(), CTX), EntityType.DOMAIN, "example.com")
    assert dom["fp_alpn"] == "http/1.1"
    assert dom["fp_http2"] is False


def test_alpn_is_offered_on_the_one_handshake_we_already_make(handshake):
    """selected_alpn_protocol() answers None unless ALPN was advertised.

    This offers it on the existing ClientHello — it does not open a second
    connection, which is the thing that is out of scope.
    """
    ctx = handshake()
    TlsCertCollector().collect(domain(), CTX)
    assert ctx.alpn_offered == ["h2", "http/1.1"]


# --- absence is absence ----------------------------------------------------

def test_a_server_that_negotiates_no_alpn_claims_nothing(handshake):
    handshake(alpn=None)
    dom = props_for(TlsCertCollector().collect(domain(), CTX), EntityType.DOMAIN, "example.com")
    assert "fp_alpn" not in dom
    assert "fp_http2" not in dom, "no ALPN means unknown, not 'not http2'"


def test_a_failed_handshake_writes_no_fingerprint_props(monkeypatch):
    """unchecked != clean: a refused connection must not produce fp_* keys."""
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr("umbra.collectors.tls_cert.socket.create_connection", boom)
    result = TlsCertCollector().collect(domain(), CTX)
    for ent in result.entities:
        assert not any(k.startswith("fp_") for k in (ent.props or {}))
    assert any("tls_cert" in n for n in result.notes)


def test_a_missing_cipher_tuple_does_not_invent_one(handshake):
    handshake(cipher=None)
    dom = props_for(TlsCertCollector().collect(domain(), CTX), EntityType.DOMAIN, "example.com")
    assert "fp_tls_cipher" not in dom
    assert dom["fp_tls_version"] == "TLSv1.3"


# --- the existing behaviour is untouched -----------------------------------

def test_the_cert_fingerprints_still_work(handshake):
    handshake()
    result = TlsCertCollector().collect(domain(), CTX)
    cert = props_for(result, EntityType.CERT)
    assert cert["fingerprint_sha256"] == hashlib.sha256(b"fake-der-bytes").hexdigest()
    assert cert["sha1"] == hashlib.sha1(b"fake-der-bytes").hexdigest()


def test_no_new_entity_type_is_introduced(handshake):
    handshake()
    result = TlsCertCollector().collect(domain(), CTX)
    assert {e.type for e in result.entities} <= {
        EntityType.DOMAIN, EntityType.CERT, EntityType.ORG
    }


# ===========================================================================
# http_probe — header order and Server, from the GET it already makes
# ===========================================================================

import hashlib as _hashlib  # noqa: E402

import httpx  # noqa: E402
import respx  # noqa: E402

from umbra.collectors.http_probe import (  # noqa: E402
    HttpProbeCollector,
    header_order_sha256,
)

HTML = b"<html><head><title>Hi</title></head><body>x</body></html>"


def http_ctx():
    return SimpleNamespace(
        settings=SimpleNamespace(request_timeout_s=10.0, user_agent="umbra-test"),
        case_id="c", run_id="r", http=httpx.Client(),
    )


def test_the_hash_is_exactly_the_documented_recipe():
    """sha256 of the first 32 header names, lowercased, comma-joined.

    Asserted on the pure function rather than through the collector: httpx
    synthesises `content-length`, so the wire list is not the list the test
    handed in, and pinning the collector to a literal digest would really be
    pinning it to httpx's internals.
    """
    resp = httpx.Response(200, headers=[("Server", "a"), ("Date", "b"), ("X-Powered-By", "c")])
    names = [k.decode() for k, _ in resp.headers.raw]
    assert header_order_sha256(resp) == _hashlib.sha256(
        ",".join(n.lower() for n in names[:32]).encode()).hexdigest()


def test_the_recipe_lowercases():
    upper = httpx.Response(200, headers=[("SERVER", "a")])
    lower = httpx.Response(200, headers=[("server", "a")])
    assert header_order_sha256(upper) == header_order_sha256(lower)


def test_a_response_with_no_headers_hashes_to_nothing():
    class _Bare:
        headers = SimpleNamespace(raw=[], items=lambda: [])

    assert header_order_sha256(_Bare()) is None


@respx.mock
def test_the_collector_records_a_header_order_hash():
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200, content=HTML, headers=[("Server", "v"), ("X-Powered-By", "v")]))
    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert len(dom["fp_header_order_sha256"]) == 64


@respx.mock
def test_a_different_order_of_the_same_headers_hashes_differently():
    """Order is the whole signal — a set would carry none of it."""
    a = ["Server", "Date", "Content-Type"]
    b = ["Date", "Content-Type", "Server"]
    hashes = []
    for names in (a, b):
        respx.get("https://example.com/").mock(return_value=httpx.Response(
            200, content=HTML, headers=[(n, "v") for n in names]))
        res = HttpProbeCollector().collect(domain(), http_ctx())
        hashes.append(props_for(res, EntityType.DOMAIN, "example.com")["fp_header_order_sha256"])
    assert hashes[0] != hashes[1]


@respx.mock
def test_header_values_are_never_hashed_only_names():
    """Values carry cookies and session ids; names carry the stack shape."""
    names = ["Server", "Set-Cookie"]
    first, second = [], []
    for value in ("secret-one", "secret-two"):
        respx.get("https://example.com/").mock(return_value=httpx.Response(
            200, content=HTML, headers=[(n, value) for n in names]))
        res = HttpProbeCollector().collect(domain(), http_ctx())
        (first if value.endswith("one") else second).append(
            props_for(res, EntityType.DOMAIN, "example.com")["fp_header_order_sha256"])
    assert first == second


def test_headers_past_the_first_32_do_not_change_the_hash():
    """Past 32 it is mostly per-response noise — caching, tracing, counters."""
    base = [(f"X-H{i}", "v") for i in range(32)]
    short = httpx.Response(200, headers=base)
    long = httpx.Response(200, headers=base + [("X-Extra", "v"), ("X-More", "v")])
    assert header_order_sha256(short) == header_order_sha256(long)

    differs_inside_the_window = httpx.Response(
        200, headers=[("X-Different", "v")] + base[1:])
    assert header_order_sha256(short) != header_order_sha256(differs_inside_the_window)


@respx.mock
def test_server_header_is_recorded_as_fp_server():
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200, content=HTML, headers={"Server": "nginx/1.24.0"}))
    res = HttpProbeCollector().collect(domain(), http_ctx())
    assert props_for(res, EntityType.DOMAIN, "example.com")["fp_server"] == "nginx/1.24.0"


@respx.mock
def test_a_server_that_sends_no_server_header_claims_none():
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200, content=HTML, headers={"Date": "now"}))
    res = HttpProbeCollector().collect(domain(), http_ctx())
    dom = props_for(res, EntityType.DOMAIN, "example.com")
    assert "fp_server" not in dom
    assert dom["fp_header_order_sha256"]


@respx.mock
def test_a_failed_fetch_writes_no_fingerprint_props():
    """unchecked != clean, on the HTTP side too."""
    respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    respx.get("http://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    res = HttpProbeCollector().collect(domain(), http_ctx())
    for ent in res.entities:
        assert not any(k.startswith("fp_") for k in (ent.props or {}))
    assert res.notes


# ===========================================================================
# favicon — same origin as the HTML that already succeeded, and one collector
# ===========================================================================

ICON = b"\x00\x00\x01\x00fake-icon-bytes"


@respx.mock
def test_favicon_is_hashed_from_the_origin_that_answered():
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200, content=HTML, headers={"Server": "nginx"}))
    respx.get("https://example.com/favicon.ico").mock(return_value=httpx.Response(
        200, content=ICON))

    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert dom["fp_favicon_sha256"] == _hashlib.sha256(ICON).hexdigest()
    assert dom["fp_favicon_bytes"] == len(ICON)


@respx.mock
def test_no_favicon_request_is_made_when_the_html_fetch_failed():
    """The favicon rides on a fetch that already worked; it never leads."""
    respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    respx.get("http://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    icon = respx.get("https://example.com/favicon.ico").mock(
        return_value=httpx.Response(200, content=ICON))

    HttpProbeCollector().collect(domain(), http_ctx())
    assert not icon.called


@respx.mock
def test_the_favicon_follows_the_redirect_target_not_the_seed():
    """Same origin means the origin that actually served the HTML."""
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        301, headers={"Location": "https://www.example.net/"}))
    respx.get("https://www.example.net/").mock(return_value=httpx.Response(
        200, content=HTML))
    wrong = respx.get("https://example.com/favicon.ico").mock(
        return_value=httpx.Response(200, content=b"wrong"))
    right = respx.get("https://www.example.net/favicon.ico").mock(
        return_value=httpx.Response(200, content=ICON))

    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert right.called and not wrong.called
    assert dom["fp_favicon_sha256"] == _hashlib.sha256(ICON).hexdigest()


@respx.mock
def test_a_missing_favicon_claims_nothing():
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, content=HTML))
    respx.get("https://example.com/favicon.ico").mock(return_value=httpx.Response(404))

    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert "fp_favicon_sha256" not in dom
    assert "fp_favicon_bytes" not in dom


@respx.mock
def test_an_empty_favicon_is_not_a_fingerprint():
    """Plenty of hosts answer 200 with zero bytes; hashing that collides
    every one of them onto the same digest."""
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, content=HTML))
    respx.get("https://example.com/favicon.ico").mock(return_value=httpx.Response(
        200, content=b""))

    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert "fp_favicon_sha256" not in dom


@respx.mock
def test_a_favicon_error_does_not_break_the_probe():
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200, content=HTML, headers={"Server": "nginx"}))
    respx.get("https://example.com/favicon.ico").mock(
        side_effect=httpx.ConnectError("refused"))

    dom = props_for(HttpProbeCollector().collect(domain(), http_ctx()),
                    EntityType.DOMAIN, "example.com")
    assert dom["fp_server"] == "nginx"          # the probe still delivered
    assert "fp_favicon_sha256" not in dom


def test_only_http_probe_fetches_the_favicon():
    """One collector, not both — otherwise an authorized lookup makes the
    same request twice and the count of requests stops matching the story."""
    from pathlib import Path

    tech = Path("src/umbra/collectors/tech_fingerprint.py").read_text()
    assert "favicon" not in tech.lower()


# ===========================================================================
# Egress guard on the raw socket
#
# tls_cert does not use GuardedClient — it opens socket.create_connection
# directly, so AGENTS.md §2 ("collector egress goes through http_guard") was
# not actually holding here. That was latent while only authorized CLI/case
# runs reached it. It stops being latent the moment an anonymous visitor can
# name the host, which is exactly what putting tls_cert on /reputation does.
# ===========================================================================

@pytest.mark.parametrize("target", [
    "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1",
])
def test_tls_cert_refuses_non_public_targets(target, monkeypatch):
    opened = []
    monkeypatch.setattr("umbra.collectors.tls_cert.socket.create_connection",
                        lambda *a, **k: opened.append(a) or _FakeConn())

    result = TlsCertCollector().collect(domain(target), CTX)
    assert not opened, f"opened a socket to {target}"
    assert any("tls_cert" in n for n in result.notes)
    for ent in result.entities:
        assert not any(k.startswith("fp_") for k in (ent.props or {}))


def test_a_host_that_does_not_resolve_is_refused(monkeypatch):
    """Fail closed: nothing resolved means nothing was checked."""
    opened = []
    monkeypatch.setattr("umbra.collectors.tls_cert.resolve_all", lambda h: [])
    monkeypatch.setattr("umbra.collectors.tls_cert.socket.create_connection",
                        lambda *a, **k: opened.append(a) or _FakeConn())

    result = TlsCertCollector().collect(domain("nowhere.invalid"), CTX)
    assert not opened
    assert any("tls_cert" in n for n in result.notes)


def test_a_public_host_still_connects(handshake, monkeypatch):
    monkeypatch.setattr("umbra.collectors.tls_cert.resolve_all", lambda h: ["93.184.216.34"])
    handshake()
    dom = props_for(TlsCertCollector().collect(domain(), CTX), EntityType.DOMAIN, "example.com")
    assert dom["fp_tls_version"] == "TLSv1.3"


def test_a_name_that_resolves_into_private_space_is_refused(monkeypatch):
    """DNS rebinding shape: public-looking name, private answer."""
    opened = []
    monkeypatch.setattr("umbra.collectors.tls_cert.resolve_all", lambda h: ["10.1.2.3"])
    monkeypatch.setattr("umbra.collectors.tls_cert.socket.create_connection",
                        lambda *a, **k: opened.append(a) or _FakeConn())

    result = TlsCertCollector().collect(domain("internal.example.com"), CTX)
    assert not opened
    assert any("tls_cert" in n for n in result.notes)
