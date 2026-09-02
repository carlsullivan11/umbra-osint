"""SSRF guard for collector egress.

`POST /run` is public. That means an anonymous visitor chooses the URLs this
server fetches, and the worker sits on the Docker bridge with `postgres:5432`
and `redis:6379` one hop away — plus link-local metadata on any cloud host.
Without a guard, "run a scan on this domain" is a request to fetch anything the
server can reach, with the response body stored as evidence.

The guard resolves first and judges the *IP*, not the name, because
`internal.attacker.com` resolving to `127.0.0.1` is the whole trick. It also
re-validates every redirect hop, since a public URL that 302s to `169.254.169.254`
is the same attack with one more step.

Residual, stated plainly: this does not pin the resolved address through to the
socket, so a DNS entry that changes between the check and the connect (classic
rebinding) is not fully closed. Blocking the ranges and every hop removes the
practical attack; pinning is the follow-up.
"""
from __future__ import annotations

import pytest

from umbra.core.http_guard import BlockedAddress, GuardedClient, check_url, is_public_ip

# The addresses the audit called out by name, plus the ones that matter here.
BLOCKED_HOSTS = [
    "127.0.0.1",         # loopback
    "169.254.169.254",   # cloud metadata
    "10.1.2.3",          # RFC1918
    "172.17.0.1",        # docker bridge — postgres/redis live here
    "172.16.5.5",        # RFC1918
    "192.168.1.1",       # RFC1918
    "0.0.0.0",           # this host
    "[::1]",             # loopback v6
    "[fd00::1]",         # unique local v6
]


@pytest.mark.parametrize("host", BLOCKED_HOSTS)
def test_internal_addresses_are_refused(host):
    with pytest.raises(BlockedAddress):
        check_url(f"http://{host}/x")


def test_a_public_address_is_allowed():
    check_url("https://93.184.216.34/")  # example.com's address, a literal


def test_ip_classification():
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("169.254.169.254") is False
    assert is_public_ip("172.17.0.2") is False


def test_a_hostname_that_resolves_internally_is_refused(monkeypatch):
    """The actual attack: the name looks fine, the answer does not.
    `internal.attacker.com A 127.0.0.1` is a five-minute DNS record."""
    monkeypatch.setattr("umbra.core.http_guard.resolve_all",
                        lambda host: ["127.0.0.1"])
    with pytest.raises(BlockedAddress):
        check_url("https://looks-legit.example/")


def test_every_answer_must_be_public_not_just_the_first(monkeypatch):
    """A record set of [public, internal] must not pass on the strength of its
    first entry — the client may connect to either."""
    monkeypatch.setattr("umbra.core.http_guard.resolve_all",
                        lambda host: ["93.184.216.34", "10.0.0.5"])
    with pytest.raises(BlockedAddress):
        check_url("https://mixed.example/")


def test_a_name_that_does_not_resolve_is_refused(monkeypatch):
    """Fail closed: no answer means nothing was validated."""
    monkeypatch.setattr("umbra.core.http_guard.resolve_all", lambda host: [])
    with pytest.raises(BlockedAddress):
        check_url("https://nxdomain.example/")


# --- schemes and shapes ---------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/x",
    "data:text/plain,hi",
])
def test_only_http_and_https_are_fetched(url):
    with pytest.raises(BlockedAddress):
        check_url(url)


def test_credentials_in_the_url_are_refused():
    """`http://user:pass@host/` smuggles secrets into logs and evidence, and is
    a classic parser-confusion vector."""
    with pytest.raises(BlockedAddress):
        check_url("http://admin:hunter2@example.com/")


def test_a_url_with_no_host_is_refused():
    with pytest.raises(BlockedAddress):
        check_url("http:///nohost")


# --- redirects ------------------------------------------------------------

def test_a_redirect_into_the_network_is_refused(monkeypatch):
    """The bypass that matters: the first hop is a real public site, the second
    is the metadata service."""
    import httpx

    hops = {
        "https://public.example/": httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/"}),
        "http://169.254.169.254/latest/meta-data/": httpx.Response(200, text="creds"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return hops[str(request.url)]

    monkeypatch.setattr("umbra.core.http_guard.resolve_all",
                        lambda host: ["93.184.216.34"] if "public" in host else ["169.254.169.254"])
    client = GuardedClient(transport=httpx.MockTransport(handler))
    with pytest.raises(BlockedAddress):
        client.get("https://public.example/", follow_redirects=True)


def test_redirects_are_capped(monkeypatch):
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://public.example/next"})

    monkeypatch.setattr("umbra.core.http_guard.resolve_all", lambda host: ["93.184.216.34"])
    client = GuardedClient(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.TooManyRedirects):
        client.get("https://public.example/", follow_redirects=True)


def test_a_normal_public_redirect_still_works(monkeypatch):
    import httpx

    hops = {
        "https://public.example/": httpx.Response(
            301, headers={"location": "https://public.example/final"}),
        "https://public.example/final": httpx.Response(200, text="ok"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return hops[str(request.url)]

    monkeypatch.setattr("umbra.core.http_guard.resolve_all", lambda host: ["93.184.216.34"])
    client = GuardedClient(transport=httpx.MockTransport(handler))
    r = client.get("https://public.example/", follow_redirects=True)
    assert r.status_code == 200 and r.text == "ok"


# --- integration ----------------------------------------------------------

def test_the_orchestrator_uses_the_guarded_client():
    """Every collector shares one client from the orchestrator. Guarding it is
    what makes the guard universal rather than per-collector discipline."""
    import inspect

    from umbra.core import orchestrator

    src = inspect.getsource(orchestrator)
    assert "GuardedClient" in src
    assert "httpx.Client(" not in src, "a raw client would bypass the guard"


def test_the_guard_can_be_disabled_only_deliberately(monkeypatch):
    """An escape hatch exists for local debugging against a lab host, and it is
    off unless someone sets it."""
    monkeypatch.setenv("UMBRA_ALLOW_PRIVATE_EGRESS", "1")
    check_url("http://127.0.0.1/x")
