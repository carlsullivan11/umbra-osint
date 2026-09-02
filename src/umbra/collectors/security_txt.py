"""RFC 9116 security.txt discovery — no third-party API."""

from __future__ import annotations

import re

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, is_email
from umbra.db.schema import Entity

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$", re.M)


class SecurityTxtCollector(BaseCollector):
    name = "security_txt"
    timeout_s = 15
    inputs = {EntityType.DOMAIN}
    description = "Fetch /.well-known/security.txt and extract contacts"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        host = entity.value
        src = entity.norm_key
        urls = [
            f"https://{host}/.well-known/security.txt",
            f"https://{host}/security.txt",
            f"http://{host}/.well-known/security.txt",
        ]
        body = None
        used = None
        for url in urls:
            try:
                resp = ctx.http.get(url, follow_redirects=True)
                if resp.status_code == 200 and resp.text and "contact:" in resp.text.lower():
                    body = resp.text[:50_000]
                    used = str(resp.url)
                    break
            except Exception as exc:  # noqa: BLE001
                result.notes.append(str(exc))
        if not body:
            result.notes.append("security.txt not found")
            return result

        fields: dict[str, list[str]] = {}
        for m in _FIELD_RE.finditer(body):
            k = m.group(1).lower()
            v = m.group(2).strip()
            fields.setdefault(k, []).append(v)

        for contact in fields.get("contact", []):
            if contact.lower().startswith("mailto:"):
                em = contact.split(":", 1)[1].strip()
                if is_email(em):
                    result.entities.append(EntityIn(type=EntityType.EMAIL, value=em, confidence=0.85))
                    result.edges.append(
                        EdgeIn(
                            source_key=src,
                            target_key=entity_key(EntityType.EMAIL, em),
                            rel=EdgeType.SECURITY_CONTACT,
                            confidence=0.85,
                        )
                    )
            elif contact.startswith("http"):
                result.entities.append(EntityIn(type=EntityType.URL, value=contact, confidence=0.8))
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.URL, contact),
                        rel=EdgeType.SECURITY_CONTACT,
                        confidence=0.8,
                    )
                )
            else:
                for em in _EMAIL_RE.findall(contact):
                    result.entities.append(EntityIn(type=EntityType.EMAIL, value=em, confidence=0.8))
                    result.edges.append(
                        EdgeIn(
                            source_key=src,
                            target_key=entity_key(EntityType.EMAIL, em),
                            rel=EdgeType.SECURITY_CONTACT,
                            confidence=0.8,
                        )
                    )

        for policy in fields.get("policy", [])[:5]:
            if policy.startswith("http"):
                result.entities.append(EntityIn(type=EntityType.URL, value=policy, confidence=0.7))

        result.entities.append(
            EntityIn(
                type=EntityType.DOMAIN,
                value=host,
                confidence=0.9,
                props={"security_txt": {k: v[:5] for k, v in fields.items()}},
            )
        )
        result.entities.append(EntityIn(type=EntityType.URL, value=used or urls[0], confidence=0.9))
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="security.txt",
                source_url=used,
                summary=f"security.txt for {host}: fields={list(fields.keys())}",
                confidence=0.9,
                raw={"fields": fields, "url": used},
                entity_key=src,
            )
        )
        return result
