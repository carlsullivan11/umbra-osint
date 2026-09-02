"""Gravatar presence from email MD5 — open protocol, no paid API."""

from __future__ import annotations

import hashlib

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class GravatarCollector(BaseCollector):
    name = "gravatar"
    timeout_s = 15
    inputs = {EntityType.EMAIL}
    description = "Gravatar profile/avatar discovery via email hash (no API key)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        email = entity.value.strip().lower()
        src = entity.norm_key
        digest = hashlib.md5(email.encode("utf-8")).hexdigest()
        # d=404 makes missing avatars return 404 instead of default mystery person
        avatar = f"https://www.gravatar.com/avatar/{digest}?d=404&s=200"
        profile = f"https://www.gravatar.com/{digest}"
        profile_json = f"https://en.gravatar.com/{digest}.json"

        try:
            av = ctx.http.get(avatar)
            has_avatar = av.status_code == 200
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"gravatar avatar: {exc}")
            has_avatar = False

        profile_data = None
        display = None
        urls: list[str] = []
        try:
            pr = ctx.http.get(profile_json)
            if pr.status_code == 200:
                profile_data = pr.json()
                entries = profile_data.get("entry") or []
                if entries:
                    ent0 = entries[0]
                    display = ent0.get("displayName") or ent0.get("preferredUsername")
                    if ent0.get("preferredUsername"):
                        result.entities.append(
                            EntityIn(
                                type=EntityType.USERNAME,
                                value=f"gravatar:{ent0['preferredUsername']}",
                                confidence=0.75,
                            )
                        )
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(
                                    EntityType.USERNAME, f"gravatar:{ent0['preferredUsername']}"
                                ),
                                rel=EdgeType.HAS_PROFILE,
                                confidence=0.75,
                            )
                        )
                    if ent0.get("name") and isinstance(ent0["name"], dict):
                        fn = ent0["name"].get("formatted")
                        if fn:
                            result.entities.append(
                                EntityIn(type=EntityType.PERSON, value=fn, confidence=0.5)
                            )
                            result.edges.append(
                                EdgeIn(
                                    source_key=entity_key(EntityType.PERSON, fn),
                                    target_key=src,
                                    rel=EdgeType.USES_EMAIL,
                                    confidence=0.45,
                                )
                            )
                    for u in ent0.get("urls") or []:
                        val = u.get("value") if isinstance(u, dict) else None
                        if val:
                            urls.append(val)
                    for acc in ent0.get("accounts") or []:
                        url = acc.get("url")
                        uname = acc.get("username")
                        domain = (acc.get("domain") or "").lower()
                        if url:
                            urls.append(url)
                        if uname and domain:
                            plat = domain.split(".")[0]
                            result.entities.append(
                                EntityIn(
                                    type=EntityType.USERNAME,
                                    value=f"{plat}:{uname}",
                                    confidence=0.6,
                                )
                            )
                            result.edges.append(
                                EdgeIn(
                                    source_key=src,
                                    target_key=entity_key(EntityType.USERNAME, f"{plat}:{uname}"),
                                    rel=EdgeType.SAME_AS,
                                    confidence=0.55,
                                )
                            )
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"gravatar json: {exc}")

        for u in urls[:15]:
            result.entities.append(EntityIn(type=EntityType.URL, value=u, confidence=0.65))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, u),
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.65,
                )
            )
            if "://" in u:
                host = u.split("://", 1)[1].split("/", 1)[0].lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.5))

        result.entities.append(
            EntityIn(
                type=EntityType.EMAIL,
                value=email,
                confidence=0.9,
                props={
                    "gravatar_hash": digest,
                    "gravatar_avatar": has_avatar,
                    "gravatar_display": display,
                },
            )
        )
        if has_avatar:
            result.entities.append(EntityIn(type=EntityType.URL, value=avatar.split("?")[0], confidence=0.8))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, avatar.split("?")[0]),
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.8,
                )
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="Gravatar",
                source_url=profile,
                summary=f"Gravatar {email}: avatar={has_avatar} display={display!r} urls={len(urls)}",
                confidence=0.85 if has_avatar or profile_data else 0.5,
                raw={"hash": digest, "has_avatar": has_avatar, "profile": profile_data},
                entity_key=src,
            )
        )
        return result
