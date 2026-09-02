"""Domains where the public uploads the content, and the site is not the author.

`github.com` and `drive.google.com` both came back **suspicious, 60/100** on
2026-09-01. The listings were real: URLhaus and ThreatFox held genuine malware
URLs. Every one of them pointed at a file a stranger had uploaded —

    github.com served https://github.com/kaswareteam/dcent/releases/.../Installer.zip

— which is a fact about a file, not about GitHub. Any platform that lets the
public upload accumulates these permanently, so scoring the apex domain by them
mostly measures how popular the platform is. A stranger checking `github.com`
and being told it is suspicious learns nothing true and stops trusting the
tool.

So these domains are named, and a **content-scope** listing on one of them is
reported without being allowed to set the verdict. Two things that does *not*
change:

- a **domain-scope** listing still condemns them. If Spamhaus lists the domain
  itself, being popular is no defence.
- the finding is never hidden. "Malware has been distributed through this
  domain" is worth knowing, and it gets its own section instead of a verdict.

**This list is a judgement, and a short one.** It is not a reputation
allowlist and must never grow into one — nothing here is trusted, and adding a
domain only changes which *kind* of evidence may set its verdict. The entry
criterion is narrow: the public can publish files or text under the domain
without the operator reviewing them first.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Platform:
    """A domain whose content is supplied by its users."""

    domain: str
    label: str
    #: What the operator actually runs, so the caution can be specific.
    kind: str  # code_hosting | file_sharing | paste | chat | cloud_storage
    caution: str


PLATFORMS: tuple[Platform, ...] = (
    Platform("github.com", "GitHub", "code_hosting",
             "Anyone can publish a repository or a release binary here, so a "
             "malicious file found on this domain says nothing about the site."),
    Platform("gitlab.com", "GitLab", "code_hosting",
             "Anyone can publish a repository or a release binary here, so a "
             "malicious file found on this domain says nothing about the site."),
    Platform("bitbucket.org", "Bitbucket", "code_hosting",
             "Anyone can publish a repository here, so a malicious file found "
             "on this domain says nothing about the site."),
    Platform("sourceforge.net", "SourceForge", "code_hosting",
             "Anyone can publish a project and its downloads here, so a "
             "malicious file found on this domain says nothing about the site."),
    Platform("drive.google.com", "Google Drive", "cloud_storage",
             "Anyone can share a file from their own Drive, so a malicious "
             "file found on this domain says nothing about the site."),
    Platform("docs.google.com", "Google Docs", "cloud_storage",
             "Anyone can publish a document here, so content found on this "
             "domain says nothing about the site."),
    Platform("dropbox.com", "Dropbox", "file_sharing",
             "Anyone can share a file from their own account, so a malicious "
             "file found on this domain says nothing about the site."),
    Platform("onedrive.live.com", "OneDrive", "file_sharing",
             "Anyone can share a file from their own account, so a malicious "
             "file found on this domain says nothing about the site."),
    Platform("mega.nz", "MEGA", "file_sharing",
             "Anyone can share a file from their own account, so a malicious "
             "file found on this domain says nothing about the site."),
    Platform("mediafire.com", "MediaFire", "file_sharing",
             "Anyone can upload and share a file here, so a malicious file "
             "found on this domain says nothing about the site."),
    Platform("wetransfer.com", "WeTransfer", "file_sharing",
             "Anyone can send a file through this service, so a malicious file "
             "found on this domain says nothing about the site."),
    Platform("discord.com", "Discord", "chat",
             "Anyone can attach a file to a message here, so a malicious file "
             "found on this domain says nothing about the site."),
    Platform("discordapp.com", "Discord (CDN)", "chat",
             "Anyone can attach a file to a message here, so a malicious file "
             "found on this domain says nothing about the site."),
    Platform("t.me", "Telegram", "chat",
             "Anyone can post a file to a channel here, so a malicious file "
             "found on this domain says nothing about the site."),
    Platform("pastebin.com", "Pastebin", "paste",
             "Anyone can publish text here anonymously, so content found on "
             "this domain says nothing about the site."),
    Platform("ghostbin.com", "Ghostbin", "paste",
             "Anyone can publish text here anonymously, so content found on "
             "this domain says nothing about the site."),
    Platform("archive.org", "Internet Archive", "file_sharing",
             "Anyone can upload an item here, and the archive also mirrors "
             "third-party pages, so content found on this domain says nothing "
             "about the site."),
    Platform("amazonaws.com", "Amazon S3", "cloud_storage",
             "Any customer can serve files from a bucket under this domain, so "
             "a malicious file found here says nothing about the provider."),
    Platform("storage.googleapis.com", "Google Cloud Storage", "cloud_storage",
             "Any customer can serve files from a bucket under this domain, so "
             "a malicious file found here says nothing about the provider."),
    Platform("blob.core.windows.net", "Azure Blob Storage", "cloud_storage",
             "Any customer can serve files from a container under this domain, "
             "so a malicious file found here says nothing about the provider."),
    Platform("firebasestorage.googleapis.com", "Firebase Storage", "cloud_storage",
             "Any developer can serve files from a bucket under this domain, so "
             "a malicious file found here says nothing about the provider."),
    Platform("cloudfront.net", "CloudFront", "cloud_storage",
             "Any customer can serve content through this CDN, so a malicious "
             "file found here says nothing about the provider."),
)

_BY_DOMAIN = {p.domain: p for p in PLATFORMS}


def lookup_platform(host: str) -> Platform | None:
    """The platform this host belongs to, or None.

    Matches the host itself or any subdomain of a listed domain. Deliberately
    **not** a substring test: `github.com.evil.tk` is not GitHub, and treating
    it as one would hand an attacker the exemption by naming their domain
    carefully.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return None
    if h in _BY_DOMAIN:
        return _BY_DOMAIN[h]
    for domain, platform in _BY_DOMAIN.items():
        if h.endswith("." + domain):
            return platform
    return None
