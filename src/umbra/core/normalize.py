from __future__ import annotations

import re
from urllib.parse import urlparse

from umbra.core.mac import canonical_mac
from umbra.core.models import EntityType

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_value(entity_type: EntityType | str, value: str) -> str:
    t = EntityType(entity_type) if not isinstance(entity_type, EntityType) else entity_type
    v = (value or "").strip()
    if not v:
        raise ValueError(f"empty value for type {t}")
    if t == EntityType.DOMAIN:
        v = v.lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        v = v.split(":")[0]  # strip accidental port
        if v.startswith("www."):
            # keep www as distinct? normalize apex preference: strip www for merge key
            v = v[4:]
        v = v.rstrip(".")
        if not v or v == "." or " " in v:
            raise ValueError(f"invalid domain: {value!r}")
        return v
    if t == EntityType.EMAIL:
        return v.lower()
    if t == EntityType.IP:
        return v.split("%")[0]
    if t == EntityType.URL:
        p = urlparse(v if "://" in v else f"https://{v}")
        netloc = p.netloc.lower()
        path = p.path.rstrip("/") or ""
        return f"{p.scheme.lower()}://{netloc}{path}"
    if t == EntityType.USERNAME:
        if ":" not in v:
            return f"unknown:{v.lower().lstrip('@')}"
        platform, handle = v.split(":", 1)
        return f"{platform.lower()}:{handle.lower().lstrip('@')}"
    if t == EntityType.ASN:
        v = v.upper().replace("AS", "").strip()
        return f"AS{v}"
    if t == EntityType.MALWARE:
        # Family names are curated, not standardised: abuse.ch writes "Cobalt
        # Strike", others write "CobaltStrike". Folding case and separators is
        # enough to merge those two; genuine aliases (Vidar / VidarStealer) are
        # a documented limitation, not something a regex can fix.
        return re.sub(r"[^a-z0-9]+", "", v.lower()) or v.strip().lower()
    if t in {EntityType.ORG, EntityType.PERSON, EntityType.TECHNOLOGY,
             EntityType.REGISTRAR, EntityType.LOCATION}:
        return re.sub(r"\s+", " ", v).strip().lower()
    if t == EntityType.REPO:
        return v.lower().removeprefix("https://github.com/").strip("/")
    if t == EntityType.VULNERABILITY:
        # Canonical CVE id, upper-cased — the same string the wiki corpus uses
        # as a slug, so the entity and its page are one identifier.
        v = v.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", v):
            raise ValueError(f"invalid CVE id: {value!r}")
        return v
    if t == EntityType.MAC:
        # Canonical colon form, upper-case, so the same NIC pasted from a DHCP
        # export, a switch CAM table and an EDR alert is one entity.
        return canonical_mac(v)
    if t == EntityType.PHONE:
        # Canonical E.164 via libphonenumber — same merge key for every paste format.
        from umbra.phone.normalize import normalize_phone

        e164 = normalize_phone(v)
        if not e164:
            raise ValueError(f"invalid phone number: {value!r}")
        return e164
    if t == EntityType.AIRCRAFT:
        # Canonical N-number, so "N-123AB", "n123ab" and the FAA file's own
        # "123AB" are one entity rather than three.
        from umbra.lake.faa import normalize_n_number

        n = normalize_n_number(v)
        if not n:
            raise ValueError(f"invalid N-number: {value!r}")
        return n
    if t == EntityType.CRYPTO_ADDRESS:
        from umbra.crypto.normalize import detect_and_normalize

        # Allow "eth:0x…" or a raw address. Unrecognised formats stay as-is so
        # the seed is still visible on the plan (operator can drop it).
        if ":" in v and not v.startswith("0x"):
            chain, _, rest = v.partition(":")
            n = detect_and_normalize(rest, chain_hint=chain)
        else:
            n = detect_and_normalize(v)
        if n:
            return f"{n.chain}:{n.address}"
        return v.strip()
    return v


def entity_key(entity_type: EntityType | str, value: str) -> str:
    t = EntityType(entity_type) if not isinstance(entity_type, EntityType) else entity_type
    return f"{t.value}:{normalize_value(t, value)}"


def parent_domain(domain: str) -> str | None:
    d = normalize_value(EntityType.DOMAIN, domain)
    parts = d.split(".")
    if len(parts) <= 2:
        return None
    # naive eTLD+1 (good enough for MVP; can swap tldextract later)
    return ".".join(parts[-2:])


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


#: File extensions that mark a URL as a resource a page *references* rather than
#: a page worth investigating. Fonts, styles, scripts, images, media, manifests
#: and feeds — things a browser fetches to render, not things a person reads.
_ASSET_SUFFIXES = frozenset({
    # images
    "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "tiff",
    # styles and scripts
    "css", "js", "mjs", "map",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # media
    "mp3", "mp4", "webm", "ogg", "wav", "avi", "mov", "m3u8", "ts",
    # documents a crawler should not treat as navigation
    "zip", "gz", "tar", "rar", "7z", "dmg", "exe", "msi", "apk",
    # machine-readable page furniture
    "webmanifest", "xml", "rss", "atom",
})


def is_static_asset(url: str) -> bool:
    """True when a URL points at page furniture rather than a page.

    `html_links` extracts with a regex matching **every** `href`, not only
    `<a href>`, so `<link rel="icon">`, stylesheets, manifests and RSS feeds all
    became URL entities. On one production search that turned 42 discovered URLs
    into 126 evidence rows — `http_probe`, `tech_fingerprint` and `html_links`
    re-run on each — burying the real answer and spending 42 requests on someone
    else's host to fingerprint their favicons.

    Judged on the **last path segment only**, and only when it actually carries
    an extension. `/css-frameworks` and `/blog/png-vs-webp` are articles; a naive
    substring test would drop them.
    """
    text = (url or "").strip()
    if not text:
        return False
    # Strip query and fragment: `/a.png?v=8e1bcc8f82` is still a PNG, and
    # `/search?q=logo.png` is still a search page.
    path = text.split("#", 1)[0].split("?", 1)[0]
    if "://" in path:
        path = path.split("://", 1)[1]
        path = path[path.find("/"):] if "/" in path else ""
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in last:
        return False
    return last.rsplit(".", 1)[-1].lower() in _ASSET_SUFFIXES
