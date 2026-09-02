"""Offline crypto address screen against the owned OFAC / label lake.

Same data as `umbra crypto screen` and `POST /crypto/screen`. A miss is
*unchecked* when the lake is empty — never a clean bill of health.
"""

from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EntityIn, EntityType, EvidenceIn
from umbra.crypto import lake as crypto_lake
from umbra.crypto.normalize import detect_and_normalize
from umbra.db.schema import Entity
from umbra.lake.store import LakeStore

_SCOPE = (
    "Owned label lake only (OFAC + curated). A tag is a risk signal with "
    "provenance, not a determination of guilt. Absence is not proof the "
    "address is clean."
)


class CryptoScreenCollector(BaseCollector):
    name = "crypto_screen"
    timeout_s = 10
    version = "0.1.0"
    inputs = {EntityType.CRYPTO_ADDRESS}
    description = (
        "Screen a crypto address against Umbra's owned OFAC/curated label lake "
        "(offline; same as `umbra crypto screen` / `/crypto`)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        result.notes.append(_SCOPE)
        raw = (entity.value or "").strip()
        n = None
        if ":" in raw and not raw.startswith("0x"):
            chain, _, rest = raw.partition(":")
            n = detect_and_normalize(rest, chain_hint=chain)
        if n is None:
            n = detect_and_normalize(raw)
        if n is None:
            result.notes.append(f"Unrecognised crypto address: {raw!r}")
            return result

        store = LakeStore.from_settings(ctx.settings)
        screened = crypto_lake.screen(store, n.chain, n.address)
        canonical = f"{n.chain}:{n.address}"
        labels = screened.get("labels") or []
        tags = [lab.get("tag") for lab in labels if lab.get("tag")]
        checked = bool(screened.get("checked"))
        sanctioned = bool(screened.get("sanctioned"))

        if not checked:
            result.notes.append(
                "Label lake empty on this instance — run `umbra crypto labels sync`. "
                "Not checked is not clean."
            )
        elif not labels:
            result.notes.append(
                "No active labels on lists Umbra has indexed. Absence is not cleanliness."
            )
        else:
            result.notes.append(
                f"{len(labels)} active label(s): {', '.join(tags[:8])}"
            )

        result.entities.append(
            EntityIn(
                type=EntityType.CRYPTO_ADDRESS,
                value=canonical,
                confidence=0.95 if sanctioned else (0.85 if labels else 0.7),
                props={
                    "crypto_chain": n.chain,
                    "crypto_address": n.address,
                    "crypto_checked": checked,
                    "crypto_sanctioned": sanctioned,
                    "crypto_labels": tags,
                    "crypto_label_count": len(labels),
                    "crypto_services": screened.get("services") or [],
                },
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="umbra crypto label lake",
                source_url=None,
                summary=(
                    f"{canonical}: sanctioned={sanctioned} labels={len(labels)} "
                    f"checked={checked}"
                ),
                confidence=0.9 if checked else 0.3,
                raw={
                    "chain": n.chain,
                    "address": n.address,
                    "checked": checked,
                    "sanctioned": sanctioned,
                    "labels": labels[:20],
                    "former_labels": (screened.get("former_labels") or [])[:10],
                    "services": screened.get("services") or [],
                },
                entity_key=entity.norm_key,
            )
        )
        return result
