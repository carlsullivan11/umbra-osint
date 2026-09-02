"""TCP connect scanning, gated on the authorization Umbra already records.

Everything else in this codebase is passive. This module is not — it sends
packets to a host, and that is a different kind of act. `docs/ETHICS.md` draws
the line at *unauthorized* intrusion, not at active technique, and the
architecture already carries the field that decides which side of the line a
given scan falls on: every case has an `authorization_basis`.

So the gate is structural rather than a promise in a docstring:

    own_asset          allowed — your own infrastructure
    client_engagement  allowed — you have a signed scope
    training_lab       allowed — a range built to be scanned
    public_cti         REFUSED — an address off a threat feed is not yours
    other              REFUSED — if the basis cannot be named, do not send packets

`public_cti` is the interesting one. It is the basis most Umbra searches use,
and it is exactly the case where scanning would be wrong: finding an IP in a
malware feed gives you no authority over it.

**What this deliberately is not.** No SYN or FIN scanning — those need raw
sockets and exist to avoid appearing in the target's logs, which is an evasion
property and not something a defensive tool should offer. No OS fingerprinting,
no version probing, no banner exploitation. A full `connect()` is what any
ordinary client does, and it is visible in the target's logs exactly as it
should be.

**Never on the public web path.** `POST /run` is anonymous; wiring this behind
it would let a stranger point Umbra's egress IP at a third party. The collector
refuses when it cannot establish an authorized basis, and the hosted site never
supplies one.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable

#: Bases under which sending packets to a host is defensible.
ALLOWED_BASES = frozenset({"own_asset", "client_engagement", "training_lab"})

#: Ports worth asking about by default. Not 1-65535: a full sweep is slower,
#: noisier, and answers a question ("what is the complete attack surface")
#: that a connect scan from one vantage point cannot answer honestly anyway.
#: These are the services that actually turn up on exposed hosts.
DEFAULT_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306, 3389, 5432,
    5601, 5672, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9000,
    9200, 9300, 11211, 15672, 27017,
)

#: Slow enough to be a good citizen, fast enough to be useful. A connect scan
#: of 44 ports at 8 concurrent finishes in seconds against a live host and does
#: not look like an attack in anyone's IDS.
DEFAULT_CONCURRENCY = 8
DEFAULT_TIMEOUT_S = 2.0


class NotAuthorized(PermissionError):
    """Raised rather than returning empty, so a refusal can never be mistaken
    for 'scanned, nothing open'."""


@dataclass
class PortResult:
    port: int
    state: str          # open | closed | filtered
    service: str | None = None
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class ScanResult:
    host: str
    ports_scanned: int
    results: list[PortResult] = field(default_factory=list)
    started_at: float = 0.0
    duration_s: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    @property
    def filtered_ports(self) -> list[PortResult]:
        """Timed out — a firewall dropped it, or the host is slow.

        Kept distinct from `closed` on purpose. A closed port answered; a
        filtered one did not, and reporting "not open" for both would be the
        same unchecked-versus-clean confusion this codebase keeps designing
        against.
        """
        return [r for r in self.results if r.state == "filtered"]


def check_basis(authorization_basis: str | None) -> None:
    """Raise unless the basis permits sending packets."""
    basis = (authorization_basis or "").strip().lower()
    if basis not in ALLOWED_BASES:
        raise NotAuthorized(
            f"port scanning refused for authorization_basis={basis or 'unset'!r}. "
            f"Allowed: {', '.join(sorted(ALLOWED_BASES))}. Finding a host in a "
            f"threat feed does not give you authority over it."
        )


def scan_port(host: str, port: int, timeout_s: float = DEFAULT_TIMEOUT_S) -> PortResult:
    """One TCP connect. Never raises."""
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        latency = (time.monotonic() - started) * 1000
        return PortResult(port=port, state="open", latency_ms=round(latency, 1))
    except socket.timeout:
        # No answer at all. A dropped SYN looks exactly like this.
        return PortResult(port=port, state="filtered",
                          latency_ms=round((time.monotonic() - started) * 1000, 1))
    except ConnectionRefusedError:
        # Answered, with a refusal. That IS an answer: nothing listening.
        return PortResult(port=port, state="closed",
                          latency_ms=round((time.monotonic() - started) * 1000, 1))
    except OSError as exc:
        return PortResult(port=port, state="filtered", error=f"{type(exc).__name__}: {exc}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan(
    host: str,
    *,
    authorization_basis: str | None,
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    concurrency: int = DEFAULT_CONCURRENCY,
    resolve_service=None,
) -> ScanResult:
    """Connect-scan `host`. Raises NotAuthorized unless the basis permits it.

    `resolve_service` maps (port, "tcp") → service name; the IANA lake supplies
    it. Passed in rather than imported so this module stays testable with no
    lake and no network.
    """
    check_basis(authorization_basis)

    host = (host or "").strip()
    if not host:
        raise ValueError("no host to scan")

    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    started = time.monotonic()
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(scan_port, host, p, timeout_s): p for p in port_list}
        for future in as_completed(futures):
            result = future.result()
            if resolve_service and result.state == "open":
                result.service = resolve_service(result.port, "tcp")
            results.append(result)

    results.sort(key=lambda r: r.port)
    return ScanResult(
        host=host,
        ports_scanned=len(port_list),
        results=results,
        started_at=started,
        duration_s=round(time.monotonic() - started, 2),
    )
