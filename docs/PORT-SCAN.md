# Active scanning — `umbra scan ports`

Everything else in Umbra is passive. This sends packets, which is a different
kind of act, so the design is mostly about **when it refuses**.

## The gate is structural, not a promise

`docs/ETHICS.md` draws the line at *unauthorized* intrusion, not at active
technique — and the architecture already carries the field that decides which
side a given scan falls on. Every case has an `authorization_basis`:

| Basis | Scanning |
|---|---|
| `own_asset` | allowed — your own infrastructure |
| `client_engagement` | allowed — you have a signed scope |
| `training_lab` | allowed — a range built to be scanned |
| `public_cti` | **refused** |
| `other` | **refused** |

`public_cti` is the important refusal. It is the basis most Umbra searches use,
and it is exactly the case where scanning would be wrong: finding an address in
a malware feed gives you no authority over it. The refusal **raises** rather
than returning an empty result, because an empty result renders as *"scanned,
nothing open"*.

```bash
umbra scan sync-ports                     # IANA registry, ~11,700 services
umbra scan ports 10.0.0.5 \
  --basis own_asset \
  --note "home lab, my own hardware"
```

## In the browser: `/ops/scan`, and only there

The web UI has the scanner at **`/ops/scan`** — behind the operator gate
(`umbra.web.operator`), failing closed, 404 rather than 403 for anyone without a
credential. Same authority as the CLI, same `authorization_basis` gate, same
refusal for `public_cti`, plus a mandatory justification written to the audit
log and a 12-per-5-minutes rate limit.

A refused attempt is audited too — an attempt someone made and Umbra declined is
exactly the thing worth having a record of.

## The public version: `/exposure/ports`

There **is** a public port scan, and it is safe for one structural reason:

> The target is derived from the TCP connection. There is no form field for a
> host, so a visitor cannot aim it at a third party — there is nowhere to type
> one.

It answers a question people genuinely cannot answer for themselves — *"what is
reachable on the connection I am using right now?"* — and it is the useful shape
of a public scanner, as opposed to "scan anything", which is an open proxy.

### Who is entitled to consent

This is the part no technical check settles, so it is disclosed:

| Address | Handling |
|---|---|
| private / loopback | **refused** — not reachable, and a forged forwarding header must not steer this into internal space |
| CGNAT (`100.64.0.0/10`) | **refused** — behind carrier NAT the public address is the ISP's, shared with other subscribers; scanning it probes them |
| public unicast | scannable — **but may still be a corporate NAT or VPN exit** |

The last row is the hard one, and no check can tell it from a home connection.
So the page shows the exact address, states plainly that a work network, VPN or
shared Wi-Fi belongs to someone else and is not the visitor's to consent for,
and requires them to **type the address** to proceed. A one-click button is a
confirmation nobody read.

Rate limited to 4 per 10 minutes — a visitor has no reason to re-check their own
connection every few seconds, and the cap is what stops it becoming an
amplifier.

## Never a target the requester chose

`POST /run` is anonymous. A scan form that takes a **host from the requester**
would let a stranger aim Umbra's egress IP at anything — the hosted site would
become a scanning proxy, running on the operator's VPS, with the operator's
abuse contact on every packet.

Two shapes are safe, for different reasons, and the suite records both:

| Route | Why it is allowed |
|---|---|
| `/ops/scan` | operator-gated, fails closed; the requester is accountable |
| `/exposure/ports` | the target comes from the connection, never from input |

Any *third* web module reaching `umbra.scan` fails the build until someone
writes down which of those two justifications applies.

The `authorization_basis` gate cannot substitute for the operator gate: an
anonymous visitor can type `own_asset` about a host they have never owned. The
basis is only meaningful when the person asserting it is **accountable**, and
the operator credential is what makes them accountable.

That is asserted, not left to code review. `tests/test_port_scan.py` fails if any
collector imports `umbra.scan` or if a scanner reaches the default registry, and
`tests/test_web_scan.py` fails if an anonymous request ever gets anything but a
404 from `/ops/scan`.

## The passive alternative

`internetdb` reads Shodan's existing index for an address and sends it nothing,
so it runs on every authorization basis — including `public_cti`, where this
scanner refuses. It answers "what has Shodan seen here", never "what is open
now", and a Shodan miss is reported as unchecked rather than as nothing open.
See `docs/INTERNETDB.md`. It does not import `umbra.scan` and does not relax
any gate on this page.

## What it deliberately is not

- **No SYN/FIN scanning.** Needs raw sockets, and its purpose is to stay out of
  the target's logs. That is an evasion property; a defensive tool has no
  business offering it. A full `connect()` is what any client does and appears
  in the target's logs exactly as it should.
- **No OS fingerprinting, no version probing, no banner exploitation.**
- **Not 1–65535.** 44 common service ports by default. A full sweep is slower,
  noisier, and cannot honestly answer the question it appears to.

## Three states, not two

| State | Meaning |
|---|---|
| `open` | connected |
| `closed` | **refused** — that is an answer: nothing listening |
| `filtered` | no reply — dropped, or the host is slow |

`closed` and `filtered` are kept apart deliberately. Reporting "not open" for
both would be the same unchecked-versus-clean confusion the rest of the codebase
designs against, and the CLI says so: *"N ports did not answer — dropped or
slow, which is unknown rather than closed."*

## What the service name is worth

The IANA registry says what a port is **assigned** to. A service is free to
ignore that entirely, so an open 6379 is *probably* Redis and might be anything.
The name renders as an expectation, always with the caveat, never as a finding.

Ports in `SENSITIVE` (databases, container runtimes, remote desktop, file
sharing) are flagged — not as vulnerabilities, but as *"this is almost never
meant to face the internet"*, which is a narrower and more defensible claim.
