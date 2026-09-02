from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class GithubUserCollector(BaseCollector):
    name = "github_user"
    timeout_s = 20
    inputs = {EntityType.USERNAME}
    description = "GitHub public user profile + repos (free API, token optional)"

    def supports(self, entity: Entity) -> bool:
        if not super().supports(entity):
            return False
        v = entity.value.lower()
        return v.startswith("github:") or v.startswith("unknown:")

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        raw = entity.value
        handle = raw.split(":", 1)[-1].lstrip("@")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": ctx.settings.user_agent}
        if ctx.settings.github_token:
            headers["Authorization"] = f"Bearer {ctx.settings.github_token}"

        url = f"https://api.github.com/users/{handle}"
        try:
            resp = ctx.http.get(url, headers=headers)
            if resp.status_code == 404:
                result.notes.append(f"GitHub user not found: {handle}")
                return result
            if resp.status_code == 403:
                result.notes.append("GitHub API rate limited — set UMBRA_GITHUB_TOKEN")
                return result
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"github_user error: {exc}")
            return result

        src = entity.norm_key
        gh_key = entity_key(EntityType.USERNAME, f"github:{handle}")
        result.entities.append(
            EntityIn(
                type=EntityType.USERNAME,
                value=f"github:{handle}",
                display_name=data.get("name") or handle,
                confidence=0.95,
                props={
                    "bio": data.get("bio"),
                    "company": data.get("company"),
                    "blog": data.get("blog"),
                    "location": data.get("location"),
                    "twitter": data.get("twitter_username"),
                    "public_repos": data.get("public_repos"),
                    "followers": data.get("followers"),
                    "created_at": data.get("created_at"),
                },
            )
        )
        if entity.value.startswith("unknown:"):
            result.edges.append(
                EdgeIn(source_key=src, target_key=gh_key, rel=EdgeType.SAME_AS, confidence=0.7)
            )

        profile_url = data.get("html_url") or f"https://github.com/{handle}"
        result.entities.append(EntityIn(type=EntityType.URL, value=profile_url, confidence=0.95))
        result.edges.append(
            EdgeIn(source_key=gh_key, target_key=entity_key(EntityType.URL, profile_url), rel=EdgeType.HAS_PROFILE, confidence=0.95)
        )

        if data.get("name"):
            result.entities.append(
                EntityIn(type=EntityType.PERSON, value=data["name"], confidence=0.55, props={"source": "github"})
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.PERSON, data["name"]),
                    target_key=gh_key,
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.55,
                )
            )

        if data.get("company"):
            company = str(data["company"]).lstrip("@").strip()
            if company:
                result.entities.append(EntityIn(type=EntityType.ORG, value=company, confidence=0.5))
                result.edges.append(
                    EdgeIn(
                        source_key=gh_key,
                        target_key=entity_key(EntityType.ORG, company),
                        rel=EdgeType.WORKS_AT,
                        confidence=0.5,
                    )
                )

        blog = (data.get("blog") or "").strip()
        if blog:
            if not blog.startswith("http"):
                blog = "https://" + blog
            result.entities.append(EntityIn(type=EntityType.URL, value=blog, confidence=0.7))
            # try domain
            host = blog.split("://", 1)[-1].split("/", 1)[0].lower()
            if host:
                result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.7))
                result.edges.append(
                    EdgeIn(
                        source_key=gh_key,
                        target_key=entity_key(EntityType.DOMAIN, host),
                        rel=EdgeType.ASSOCIATED_WITH,
                        confidence=0.7,
                    )
                )

        if data.get("twitter_username"):
            tw = data["twitter_username"]
            result.entities.append(EntityIn(type=EntityType.USERNAME, value=f"twitter:{tw}", confidence=0.7))
            result.edges.append(
                EdgeIn(
                    source_key=gh_key,
                    target_key=entity_key(EntityType.USERNAME, f"twitter:{tw}"),
                    rel=EdgeType.SAME_AS,
                    confidence=0.65,
                )
            )

        # repos
        try:
            repos_resp = ctx.http.get(
                f"https://api.github.com/users/{handle}/repos",
                headers=headers,
                params={"per_page": 30, "sort": "updated"},
            )
            if repos_resp.status_code == 200:
                for repo in repos_resp.json()[:30]:
                    full = repo.get("full_name")
                    if not full:
                        continue
                    result.entities.append(
                        EntityIn(
                            type=EntityType.REPO,
                            value=full,
                            confidence=0.9,
                            props={
                                "description": repo.get("description"),
                                "language": repo.get("language"),
                                "html_url": repo.get("html_url"),
                                "fork": repo.get("fork"),
                            },
                        )
                    )
                    result.edges.append(
                        EdgeIn(
                            source_key=gh_key,
                            target_key=entity_key(EntityType.REPO, full),
                            rel=EdgeType.OWNS,
                            confidence=0.9,
                        )
                    )
                    if repo.get("homepage"):
                        hp = repo["homepage"]
                        if hp.startswith("http"):
                            result.entities.append(EntityIn(type=EntityType.URL, value=hp, confidence=0.6))
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"repos fetch: {exc}")

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="GitHub API",
                source_url=url,
                summary=f"GitHub user {handle}: repos={data.get('public_repos')} loc={data.get('location')!r}",
                confidence=0.95,
                raw=data,
                entity_key=gh_key,
            )
        )
        return result
