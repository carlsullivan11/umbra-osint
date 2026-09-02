"""GitHub identity without REST API: Atom feeds + optional shallow git log."""

from __future__ import annotations

import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, is_email
from umbra.db.schema import Entity

_ATOM_NS = {"a": "http://www.w3.org/2005/Atom"}
_REPO_HREF = re.compile(r'href="(/[^/]+/[^/]+)"')
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


class GithubCommitsCollector(BaseCollector):
    name = "github_commits"
    timeout_s = 90
    inputs = {EntityType.USERNAME}
    description = "GitHub emails/repos via public Atom + git log (no GitHub API)"

    def supports(self, entity: Entity) -> bool:
        if not super().supports(entity):
            return False
        v = entity.value.lower()
        return v.startswith("github:") or v.startswith("unknown:")

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        handle = entity.value.split(":", 1)[-1].lstrip("@")
        src_key = entity_key(EntityType.USERNAME, f"github:{handle}")
        # normalize github username entity
        result.entities.append(
            EntityIn(type=EntityType.USERNAME, value=f"github:{handle}", confidence=0.9)
        )
        if entity.value.startswith("unknown:"):
            result.edges.append(
                EdgeIn(source_key=entity.norm_key, target_key=src_key, rel=EdgeType.SAME_AS, confidence=0.7)
            )

        # Public SSH keys (plain text, no API)
        try:
            keys = ctx.http.get(f"https://github.com/{handle}.keys")
            if keys.status_code == 200 and keys.text.strip():
                result.entities.append(
                    EntityIn(
                        type=EntityType.USERNAME,
                        value=f"github:{handle}",
                        confidence=0.95,
                        props={"ssh_key_lines": len(keys.text.strip().splitlines())},
                    )
                )
                result.evidence.append(
                    EvidenceIn(
                        collector=self.name,
                        source_name="github.keys",
                        source_url=f"https://github.com/{handle}.keys",
                        summary=f"SSH keys published for {handle}: {len(keys.text.strip().splitlines())} line(s)",
                        confidence=0.9,
                        raw={"keys_count": len(keys.text.strip().splitlines())},
                        entity_key=src_key,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"keys: {exc}")

        # Profile HTML for display name / website / repos
        repos: list[str] = []
        try:
            prof = ctx.http.get(f"https://github.com/{handle}")
            if prof.status_code == 404:
                result.notes.append(f"GitHub user page 404: {handle}")
                return result
            html = prof.text
            # website
            for m in re.finditer(r'itemprop="url"\s+href="(https?://[^"]+)"', html):
                url = m.group(1)
                result.entities.append(EntityIn(type=EntityType.URL, value=url, confidence=0.7))
                host = url.split("://", 1)[-1].split("/", 1)[0].lower().removeprefix("www.")
                if host:
                    result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.65))
                    result.edges.append(
                        EdgeIn(
                            source_key=src_key,
                            target_key=entity_key(EntityType.DOMAIN, host),
                            rel=EdgeType.ASSOCIATED_WITH,
                            confidence=0.65,
                        )
                    )
            # repos from profile — strict path only
            repo_re = re.compile(
                rf'href="(/{re.escape(handle)}/[A-Za-z0-9_.-]+)"',
                re.I,
            )
            for m in repo_re.finditer(html):
                path = m.group(1).strip("/")
                parts = path.split("/")
                if len(parts) != 2:
                    continue
                if parts[1].lower() in {
                    "followers",
                    "following",
                    "stars",
                    "repositories",
                    "projects",
                    "packages",
                    "sponsors",
                    "lists",
                }:
                    continue
                full = f"{parts[0]}/{parts[1]}"
                if full not in repos:
                    repos.append(full)
            # also tab repos page
            tab = ctx.http.get(f"https://github.com/{handle}?tab=repositories")
            if tab.status_code == 200:
                for m in repo_re.finditer(tab.text):
                    path = m.group(1).strip("/")
                    parts = path.split("/")
                    if len(parts) == 2:
                        full = f"{parts[0]}/{parts[1]}"
                        if full not in repos:
                            repos.append(full)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"profile: {exc}")

        repos = repos[:12]
        emails: set[str] = set()
        authors: set[str] = set()

        for full in repos:
            result.entities.append(EntityIn(type=EntityType.REPO, value=full, confidence=0.85))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.REPO, full),
                    rel=EdgeType.OWNS,
                    confidence=0.85,
                )
            )
            # Atom commits feed — no API key
            atom_url = f"https://github.com/{full}/commits.atom"
            try:
                atom = ctx.http.get(atom_url)
                if atom.status_code == 200 and atom.text.strip():
                    emails_found, authors_found = _parse_atom(atom.text)
                    emails |= emails_found
                    authors |= authors_found
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"atom {full}: {exc}")

        # Shallow git log on top 3 repos for author emails (noreply + real)
        for full in repos[:3]:
            try:
                got = _git_log_emails(full, ctx.settings.request_timeout_s)
                emails |= got
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"git {full}: {exc}")

        for em in sorted(emails):
            em = em.strip().strip("<>[]").lower()
            if not is_email(em):
                continue
            # skip noise
            if em.endswith("@users.noreply.github.com") or em == "noreply@github.com":
                conf = 0.55
            elif em.endswith(".localdomain") or em.endswith(".local"):
                continue
            else:
                conf = 0.85
            result.entities.append(EntityIn(type=EntityType.EMAIL, value=em, confidence=conf))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.EMAIL, em),
                    rel=EdgeType.USES_EMAIL,
                    confidence=conf,
                )
            )
            # domain pivot
            dom = em.split("@", 1)[1]
            if not dom.endswith(".localdomain") and not dom.endswith(".local"):
                result.entities.append(EntityIn(type=EntityType.DOMAIN, value=dom, confidence=0.6))
                result.edges.append(
                    EdgeIn(
                        source_key=entity_key(EntityType.EMAIL, em),
                        target_key=entity_key(EntityType.DOMAIN, dom),
                        rel=EdgeType.LINKED_FROM,
                        confidence=0.9,
                    )
                )

        for name in sorted(authors)[:20]:
            if len(name) < 2:
                continue
            result.entities.append(
                EntityIn(type=EntityType.PERSON, value=name, confidence=0.45, props={"source": "git_author"})
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.PERSON, name),
                    target_key=src_key,
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.4,
                )
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="GitHub public (Atom/git/HTML)",
                source_url=f"https://github.com/{handle}",
                summary=f"GitHub {handle}: repos={len(repos)} emails={len(emails)} authors={len(authors)}",
                confidence=0.85,
                raw={"repos": repos, "emails": sorted(emails), "authors": sorted(authors)[:20]},
                entity_key=src_key,
            )
        )
        return result


def _parse_atom(text: str) -> tuple[set[str], set[str]]:
    emails: set[str] = set()
    authors: set[str] = set()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # fallback regex
        for em in _EMAIL_RE.findall(text):
            emails.add(em.lower())
        return emails, authors
    for entry in root.findall("a:entry", _ATOM_NS) or root.findall("entry"):
        # author
        author = entry.find("a:author", _ATOM_NS)
        if author is None:
            author = entry.find("author")
        if author is not None:
            name_el = author.find("a:name", _ATOM_NS)
            if name_el is None:
                name_el = author.find("name")
            email_el = author.find("a:email", _ATOM_NS)
            if email_el is None:
                email_el = author.find("email")
            if name_el is not None and name_el.text:
                authors.add(name_el.text.strip())
            if email_el is not None and email_el.text:
                emails.add(email_el.text.strip().strip("<>[]").lower())
        # sometimes email only in content
        content = entry.find("a:content", _ATOM_NS)
        if content is None:
            content = entry.find("content")
        if content is not None and content.text:
            for em in _EMAIL_RE.findall(content.text):
                emails.add(em.strip("<>[]").lower())
    # also scan full XML text for mailto / bare emails
    for em in _EMAIL_RE.findall(text):
        emails.add(em.strip("<>[]").lower())
    return emails, authors


def _git_log_emails(full_repo: str, timeout: float) -> set[str]:
    emails: set[str] = set()
    url = f"https://github.com/{full_repo}.git"
    with tempfile.TemporaryDirectory(prefix="umbra-git-") as td:
        dest = Path(td) / "repo"
        clone = subprocess.run(
            ["git", "clone", "--depth", "15", "--filter=blob:none", "--quiet", url, str(dest)],
            capture_output=True,
            timeout=max(45, int(timeout) + 15),
            check=False,
        )
        if clone.returncode != 0:
            return emails
        log = subprocess.run(
            ["git", "-C", str(dest), "log", "--format=%ae%n%ce"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if log.returncode == 0:
            for line in log.stdout.splitlines():
                line = line.strip().lower().strip("<>[]")
                if line and "@" in line:
                    emails.add(line)
    return emails
