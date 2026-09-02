"""Turn a KEV addition into a post worth reading.

**Why KEV and not "new CVEs".** CISA's Known Exploited Vulnerabilities catalogue
is the one vulnerability feed where every entry means the same concrete thing:
*someone is actually exploiting this.* It updates a few times a week, each entry
carries vendor, product, a federal remediation deadline and whether ransomware
crews are using it, and Umbra already holds all of it in the corpus. There is no
scraping and no invention here — the post says what the page says.

**Why the shape varies.** X's automation policy flags "identical content posted
at scale — the same tweet template with minor variations". A bot that emits
`New KEV: {cve} {link}` forever is that pattern, and it deserves to be flagged
because it is also boring.

So the lead is chosen by **what is actually true about this CVE**, not by
rotating templates at random:

    ransomware crews use it     -> lead with that, it is the sharpest fact
    EPSS puts it very high      -> lead with exploitation probability
    the federal deadline is near-> lead with the deadline
    otherwise                   -> lead with vendor, product and the weakness

Different facts produce different sentences. That is variety a policy engine
should accept, because it is not disguise — it is the content differing.

**Nothing is claimed that the page does not say.** EPSS is included only when
the lake actually has a score; `score()` returns None for unscored CVEs and the
line is dropped rather than filled with a zero. Same rule as everywhere else in
this codebase: absence is not a value.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any

#: t.co rewrites every link to a fixed width, so the URL costs the same 23
#: characters whatever it actually is. 280 - 23 - a space.
MAX_TEXT = 250

_DATE_ADDED = re.compile(r"\|\s*Date added\s*\|\s*(\d{4}-\d{2}-\d{2})", re.I)
_DUE = re.compile(r"\|\s*Due date\s*\|\s*(\d{4}-\d{2}-\d{2})", re.I)
_VENDOR = re.compile(r"\|\s*Vendor\s*/\s*project\s*\|\s*([^|\n]+)\|", re.I)
_PRODUCT = re.compile(r"\|\s*Product\s*\|\s*([^|\n]+)\|", re.I)
_RANSOM = re.compile(r"\|\s*Ransomware campaign use\s*\|\s*Known\s*\|", re.I)


@dataclass
class Candidate:
    cve: str
    slug: str
    title: str
    summary: str
    date_added: str
    due_date: str = ""
    vendor: str = ""
    product: str = ""
    ransomware: bool = False
    epss: float | None = None

    @property
    def ref(self) -> str:
        return self.cve


def _cell(pattern: re.Pattern, body: str) -> str:
    m = pattern.search(body)
    return (m.group(1).strip() if m else "").strip("* ")


def parse_kev_page(page: dict[str, Any]) -> Candidate | None:
    """A KEV wiki page as a post candidate, or None if it is not one."""
    slug = str(page.get("slug") or "")
    if not slug.startswith("cve/"):
        return None
    body = str(page.get("body") or "")
    added = _cell(_DATE_ADDED, body)
    if not added:
        # Not a KEV import (NVD-only pages have no catalogue date). Those are
        # not news — an entry is newsworthy because CISA added it.
        return None
    return Candidate(
        cve=slug.split("/", 1)[1],
        slug=slug,
        title=str(page.get("title") or ""),
        summary=str(page.get("summary") or ""),
        date_added=added,
        due_date=_cell(_DUE, body),
        vendor=_cell(_VENDOR, body),
        product=_cell(_PRODUCT, body),
        ransomware=bool(_RANSOM.search(body)),
    )


def _clip(text: str, limit: int) -> str:
    """At most `limit` characters, ellipsis included.

    The ellipsis is part of the budget, not an extra. A post one character over
    is rejected by the API, and discovering that at publish time costs a real
    call — there is no free tier to discover it on.
    """
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[: max(0, limit - 1)]
    space = cut.rfind(" ")
    return (cut[:space] if space > limit * 0.5 else cut).rstrip(" ,;:.") + "…"


def _thing(c: Candidate) -> str:
    """How to name the affected software, as specifically as the page allows."""
    vendor, product = c.vendor, c.product
    if vendor and product:
        return product if product.lower().startswith(vendor.lower()) else f"{vendor} {product}"
    return product or vendor or c.cve


def _days_until(due: str, today: date | None = None) -> int | None:
    try:
        y, m, d = (int(x) for x in due.split("-"))
        return (date(y, m, d) - (today or date.today())).days
    except Exception:  # noqa: BLE001
        return None


def compose(c: Candidate, origin: str = "https://umbra-osint.com",
            today: date | None = None) -> tuple[str, str]:
    """(text, url). The lead is picked by what is true, not by a template."""
    from umbra.wiki.parse import strip_markdown

    url = f"{origin}/wiki/p/{c.slug}"
    thing = _thing(c)
    # Defensive: the summary is usually clean, but an index built before the
    # 2026-09-01 parse fix still holds `**CISA Known Exploited Vulnerability
    # (KEV)**`. A stale index is a local inconvenience; asterisks in a
    # published post are permanent.
    detail = strip_markdown(c.summary or c.title)

    # Sharpest fact first.
    if c.ransomware:
        lead = (f"{c.cve} in {thing} is in CISA's KEV catalogue and is known to "
                f"be used in ransomware campaigns.")
    elif c.epss is not None and c.epss >= 0.5:
        lead = (f"{c.cve} in {thing} is being exploited. EPSS puts the chance of "
                f"exploitation in the next 30 days at {c.epss:.0%}.")
    else:
        days = _days_until(c.due_date, today) if c.due_date else None
        if days is not None and 0 <= days <= 21:
            lead = (f"US federal agencies have {days} day{'s' if days != 1 else ''} "
                    f"left to remediate {c.cve} in {thing} — it is on CISA's KEV list.")
        else:
            lead = f"CISA added {c.cve} in {thing} to the KEV catalogue — it is being exploited."

    # A second sentence only if it says something the lead did not.
    tail = ""
    if detail and thing.lower() not in ("", c.cve.lower()):
        candidate_tail = _clip(detail, MAX_TEXT - len(lead) - 1)
        if len(candidate_tail) > 40:
            tail = " " + candidate_tail

    return _clip(lead + tail, MAX_TEXT), url


def select(pages: list[dict[str, Any]], *, store, epss=None, limit: int = 3,
           kind: str = "kev_addition") -> list[Candidate]:
    """Newest unposted KEV entries, enriched with EPSS where it exists."""
    candidates = [c for c in (parse_kev_page(p) for p in pages) if c]
    candidates.sort(key=lambda c: c.date_added, reverse=True)

    out: list[Candidate] = []
    for c in candidates:
        if len(out) >= limit:
            break
        if store.already_posted(kind, c.ref):
            continue
        if epss is not None:
            try:
                # score() returns a dict (or None for unscored CVEs) — the
                # probability lives under "score". None stays None: an unscored
                # CVE is unmodelled, not low-risk, so the line is dropped
                # rather than rendered as 0%.
                row = epss.score(c.cve)
                c.epss = float(row["score"]) if row and row.get("score") is not None else None
            except Exception:  # noqa: BLE001
                c.epss = None
        out.append(c)
    return out
