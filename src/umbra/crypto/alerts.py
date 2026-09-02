"""Turning the index into something that tells you (C6).

C2 built a head-follower and C3 put the mixer pools in its watch set, and until
now the whole thing recorded quietly and woke nobody.

**The watch set and the alert set are deliberately different.** Pools are
watched so deposits are recorded as they happen — but a pool receives deposits
constantly, and alerting on each would produce exactly the muted channel the ops
digest was rebuilt to avoid. A stranger using a mixer is Tuesday.

What earns an alert is a **labelled** address moving: one of the OFAC entries
sending or receiving. That is rare, and it is the thing an investigator wants
pushed rather than polled. A labelled address moving *into a mixer* is the
strongest signal this module can produce and gets the higher severity.

Alerts go through `record_ops_event`, so they inherit the existing dedupe,
escalation and Telegram path rather than inventing a second notification
channel.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# A hot address can produce hundreds of transfers in one tick. Paging somebody
# three hundred times is the same as not paging them, so the rest is summarised
# in a single row rather than dropped silently.
MAX_ALERTS_PER_TICK = 10


def _amount(transfer: dict) -> str:
    try:
        raw = int(transfer.get("amount_raw") or 0)
        decimals = int(transfer.get("decimals") or 0)
    except (TypeError, ValueError):
        return "?"
    value = raw / (10 ** decimals) if decimals else raw
    return f"{value:,.6f}".rstrip("0").rstrip(".")


def _describe(store, chain: str, address: str) -> dict:
    """Why this address is interesting: labels first, service identity second."""
    from umbra.crypto.services import load_default_registry

    labels = store.crypto_labels(chain, address)
    services = load_default_registry().match(chain, address)
    return {
        "address": address,
        "labels": [
            {"tag": lab["tag"], "source": lab["source"],
             "summary": lab["summary"]}
            for lab in labels
        ],
        "services": [{"name": s.name, "kind": s.kind.value} for s in services],
    }


def raise_for_transfers(repo, store, transfers: list[dict]) -> int:
    """Emit ops events for transfers worth waking somebody. Returns the count."""
    if not transfers:
        return 0

    alertable: list[tuple[dict, dict, dict]] = []
    for transfer in transfers:
        chain = transfer.get("chain", "eth")
        sender = _describe(store, chain, transfer.get("from_addr", ""))
        receiver = _describe(store, chain, transfer.get("to_addr", ""))
        # A label on either end is the trigger. A service on either end is
        # context that raises severity, never the trigger by itself — otherwise
        # every mixer deposit on the chain becomes a page.
        if sender["labels"] or receiver["labels"]:
            alertable.append((transfer, sender, receiver))

    raised = 0
    for transfer, sender, receiver in alertable[:MAX_ALERTS_PER_TICK]:
        labelled_is_sender = bool(sender["labels"])
        subject = sender if labelled_is_sender else receiver
        other = receiver if labelled_is_sender else sender
        mixer = any(svc["kind"] == "mixer"
                    for svc in sender["services"] + receiver["services"])

        tags = ", ".join(lab["tag"] for lab in subject["labels"])
        verb = "sent" if labelled_is_sender else "received"
        title = (f"Watched address {subject['address'][:14]}… {verb} "
                 f"{_amount(transfer)} {transfer.get('asset', '')}"
                 + (" via a mixer" if mixer else ""))

        try:
            repo.record_ops_event(
                # A sanctioned address routing funds through a mixer is the
                # strongest thing this module can say. Everything else is worth
                # knowing, not worth waking up for.
                severity="S2" if mixer else "S3",
                kind="crypto_watch_hit",
                title=title[:200],
                detail={
                    "chain": transfer.get("chain"),
                    "txid": transfer.get("txid"),
                    "direction": verb,
                    "subject": subject,
                    "counterparty": other,
                    "asset": transfer.get("asset"),
                    "amount": _amount(transfer),
                    "amount_raw": str(transfer.get("amount_raw")),
                    "block_number": transfer.get("block_number"),
                    "tags": tags,
                    "mixer_involved": mixer,
                    "note": ("Movement of a labelled address. A label is a risk "
                             "signal with provenance, not a determination of "
                             "guilt, and mixer use is not a crime."),
                },
                # Per transfer, not per address: fingerprinting on the address
                # would collapse a week of movement into one row nobody looks at
                # twice.
                fingerprint=f"crypto:{transfer.get('chain')}:{transfer.get('txid')}"
                            f":{transfer.get('log_index', 0)}",
                source="crypto_tail",
            )
            raised += 1
        except Exception:  # noqa: BLE001 - an alert failing must not stop ingest
            logger.exception("could not record crypto watch alert")

    overflow = len(alertable) - raised
    if overflow > 0:
        try:
            repo.record_ops_event(
                severity="S3", kind="crypto_watch_burst",
                title=f"{overflow} more watched-address transfer(s) this tick",
                detail={"suppressed": overflow, "shown": raised,
                        "note": "Capped so a busy address cannot flood the "
                                "channel. The transfers are all in the index."},
                fingerprint="crypto:burst",
                source="crypto_tail",
            )
        except Exception:  # noqa: BLE001
            logger.exception("could not record crypto burst alert")
    return raised
