"""Parse wiki markdown pages with YAML-ish frontmatter (no PyYAML dependency).

**The summary is the search snippet.** `page.summary` becomes the
`<meta name="description">` on the public wiki page, which is the sentence a
searcher reads before deciding whether to click. It is worth more care than an
internal field usually gets.

It used to be "the first line of the body that is not a heading", taken
verbatim. For the 1,704 imported KEV pages that line is the banner
`**CISA Known Exploited Vulnerability (KEV)**` — so every one of them shipped
the *same* description, markdown asterisks included, while the real prose sat
two headings further down under `## Description`. 1,704 pages competing for
attention with one identical malformed sentence.

`summarize_body` now looks for the description where imported pages actually
put it, skips banner furniture, and strips inline markdown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Headings whose first paragraph is the page's own description. Ordered —
#: an explicit "Description" beats a general "Overview".
_SUMMARY_HEADINGS = ("description", "summary", "overview", "what it is")

#: Lines that are page furniture rather than prose. A KEV banner is entirely
#: bold with no sentence in it; tables, quotes, lists and bare links are not
#: descriptions either.
_FURNITURE = re.compile(
    r"""^(?:
          \s*\|                      # table row
        | \s*>                       # blockquote
        | \s*[-*+]\s                 # bullet
        | \s*\d+\.\s                 # numbered item
        | \s*<!--                    # html comment
        | \s*<                       # raw html
        | \s*!?\[                    # image / link-only line
        | \s*https?://               # bare url
        | \s*[-=]{3,}\s*$            # rule
    )""",
    re.X,
)

#: A line that is nothing but emphasised text — the KEV banner shape.
_EMPHASIS_ONLY = re.compile(r"^\s*[*_]{1,3}[^*_]+[*_]{1,3}\s*$")


def strip_markdown(text: str) -> str:
    """Inline markdown to plain text. Meta tags render no formatting.

    Handles *truncated* markdown as well as well-formed markdown. The MITRE
    importer clips its frontmatter summary at a fixed width, which lands
    mid-link often enough to matter: `... using [Ping](https://attack.mi` has
    no closing paren, so a regex needing one leaves the raw syntax in the
    snippet. Anything arriving here is going into a meta tag, so it gets
    cleaned whether or not the source was well-formed.
    """
    out = text
    out = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", out)     # images
    out = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", out)      # links -> label
    # Dangling link cut off by an upstream truncation — keep the label, drop
    # the half-written target.
    out = re.sub(r"\[([^\]]*)\]\([^)]*$", r"\1", out)
    out = re.sub(r"\[([^\]]*)$", r"\1", out)                # bare open bracket
    out = re.sub(r"`([^`]+)`", r"\1", out)                  # code
    out = re.sub(r"[*_]{1,3}([^*_]+)[*_]{1,3}", r"\1", out)  # bold / italic
    # ATT&CK writes source markers inline: "...harder to detect.(Citation:
    # Bitdefender FunnyDream November 2020)". They point at a reference section
    # this snippet does not carry, so out here they are noise occupying the
    # most valuable 200 characters on the page. The second pattern catches the
    # marker left unclosed by the importer's fixed-width clip.
    out = re.sub(r"\(Citation:[^)]*\)", "", out)
    out = re.sub(r"\(Citation:[^)]*$", "", out)
    out = out.replace("\\", "")
    return re.sub(r"\s+", " ", out).strip()


def _clip(text: str, limit: int = 200) -> str:
    """Truncate on a word boundary — a snippet cut mid-word looks broken."""
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    return (cut[:space] if space > limit * 0.6 else cut).rstrip(" ,;:.") + "…"


def summarize_body(body: str, limit: int = 200) -> str:
    """The best one-line description this page offers.

    Prefers the paragraph under a `## Description`-style heading, which is
    where every importer puts the real prose, and falls back to the first line
    of actual writing. Returns "" when the page genuinely has no prose — an
    empty description is better than a misleading one.
    """
    lines = body.splitlines()

    # 1. The paragraph under a description-ish heading.
    for i, raw in enumerate(lines):
        heading = re.match(r"^\s*#{1,6}\s+(.*?)\s*$", raw)
        if not heading:
            continue
        if heading.group(1).strip().lower().rstrip(":") not in _SUMMARY_HEADINGS:
            continue
        for follow in lines[i + 1:]:
            text = follow.strip()
            if not text:
                continue
            if text.startswith("#"):
                break
            if _FURNITURE.match(follow) or _EMPHASIS_ONLY.match(follow):
                continue
            cleaned = strip_markdown(text)
            if cleaned:
                return _clip(cleaned, limit)
        # The page declares "here is my description" and the section is empty.
        # Falling through to the first prose anywhere would label some other
        # section — "Apply updates." — as the description. The title is the
        # better snippet, so return nothing and let the caller fall back.
        return ""

    # 2. First line of real prose anywhere.
    for raw in lines:
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        if _FURNITURE.match(raw) or _EMPHASIS_ONLY.match(raw):
            continue
        cleaned = strip_markdown(text)
        if cleaned:
            return _clip(cleaned, limit)
    return ""


@dataclass
class WikiPage:
    slug: str
    title: str
    page_type: str
    body: str
    path: str = ""
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)
    provenance: str = "curated"
    import_source: str | None = None
    import_id: str | None = None
    updated_at: str | None = None

    @property
    def search_blob(self) -> str:
        parts = [
            self.slug,
            self.title,
            self.summary,
            self.page_type,
            " ".join(self.tags),
            " ".join(self.mitre_ids),
            " ".join(self.cve_ids),
            " ".join(self.cwe_ids),
            " ".join(self.standards),
            self.body,
        ]
        return "\n".join(p for p in parts if p)


_FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in "\"'" and raw[-1] == raw[0]:
        return raw[1:-1]
    if raw.lower() in ("null", "~", "none"):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        items = []
        for part in inner.split(","):
            items.append(_parse_scalar(part))
        return items
    return raw


def _parse_frontmatter(block: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_key: str | None = None
    list_acc: list[Any] | None = None

    def flush_list() -> None:
        nonlocal current_key, list_acc
        if current_key is not None and list_acc is not None:
            data[current_key] = list_acc
        current_key = None
        list_acc = None

    for line in block.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        # list item under key
        m_item = re.match(r"^(\s+)-\s+(.*)$", line)
        if m_item and current_key:
            if list_acc is None:
                list_acc = []
            val = m_item.group(2).strip()
            # skip nested dict sources for index simplicity
            if val.startswith("name:") or val.startswith("url:"):
                continue
            list_acc.append(_parse_scalar(val))
            continue
        m_key = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
        if m_key:
            flush_list()
            key, rest = m_key.group(1), m_key.group(2)
            if rest == "" or rest == "|" or rest == ">":
                current_key = key
                list_acc = []
                continue
            data[key] = _parse_scalar(rest)
            current_key = key if isinstance(data[key], list) else None
            list_acc = data[key] if isinstance(data.get(key), list) else None
            continue
    flush_list()
    return data


def _as_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None and str(x).strip()]
    if isinstance(val, str):
        return [val] if val.strip() else []
    return [str(val)]


def parse_wiki_markdown(text: str, path: str = "") -> WikiPage | None:
    text = text.lstrip("\ufeff")
    m = _FM_RE.match(text)
    if not m:
        return None
    meta, body = m.group(1), m.group(2).strip()
    fm = _parse_frontmatter(meta)
    slug = str(fm.get("slug") or "").strip()
    title = str(fm.get("title") or "").strip()
    if not slug or not title:
        return None
    # An author-written summary always wins; otherwise derive one that is
    # actually usable as a search snippet.
    summary = strip_markdown(str(fm.get("summary") or "").strip())
    if not summary:
        summary = summarize_body(body)
    return WikiPage(
        slug=slug,
        title=title,
        page_type=str(fm.get("page_type") or "concept"),
        body=body,
        path=path,
        summary=summary,
        tags=_as_list(fm.get("tags")),
        mitre_ids=_as_list(fm.get("mitre_ids")),
        cve_ids=_as_list(fm.get("cve_ids")),
        cwe_ids=_as_list(fm.get("cwe_ids")),
        standards=_as_list(fm.get("standards")),
        related=_as_list(fm.get("related")),
        provenance=str(fm.get("provenance") or "curated"),
        import_source=(str(fm["import_source"]) if fm.get("import_source") else None),
        import_id=(str(fm["import_id"]) if fm.get("import_id") else None),
        updated_at=(str(fm["updated_at"]) if fm.get("updated_at") else None),
    )


def load_corpus(corpus_dir: Path) -> list[WikiPage]:
    pages: list[WikiPage] = []
    if not corpus_dir.is_dir():
        return pages
    for path in sorted(corpus_dir.rglob("*.md")):
        if path.name.upper() in ("README.MD", "SCHEMA.MD", "CONTRIBUTING.MD", "LICENSE"):
            continue
        if path.parts and path.parts[-2:] == ("meta",):
            continue
        # skip top-level docs
        rel = path.relative_to(corpus_dir)
        if len(rel.parts) == 1 and rel.suffix == ".md":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        page = parse_wiki_markdown(text, path=str(path))
        if page:
            pages.append(page)
    return pages
