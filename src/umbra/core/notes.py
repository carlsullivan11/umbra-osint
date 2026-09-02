"""Make a run's notes readable.

Umbra's rule is that an unchecked source must never render as a clean result,
so collectors say out loud whenever they could not look. That rule is right and
it stays. What broke is the presentation: a three-seed run printed **33 note
lines carrying 15 distinct conditions**, the same "GeoIP lake not loaded" four
times and "abuse lake never synced" six. At that length nobody reads any of
them, so the one note that mattered — crt.sh was down, meaning certificate
coverage was incomplete — was buried among chores.

Two things fix it, and they are separate:

**Aggregate.** One line per condition, with the subjects it affected. Four IPs
with no geolocation is one fact about the run, not four.

**Classify.** The list currently mixes three statements that ask for three
different reactions from the reader:

- a **result** — "reputation: clean, 0/2 sources listed" is the answer, not a
  warning about the answer;
- a **chore** — "abuseipdb: skipped (no key)" is something the operator can fix
  once and never see again;
- a **coverage gap** — "crt.sh unavailable (HTTP 502)" is nobody's fault, will
  probably fix itself, and is the only one that changes how much you should
  trust this particular run.

Rendering all three in one undifferentiated block is why the wall is unreadable.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum


class NoteKind(str, Enum):
    """Why this line is on the page, which decides where it belongs."""

    RESULT = "result"
    """An answer. Belongs with the findings."""

    NOT_CONFIGURED = "not_configured"
    """The operator can make this go away — a key, a sync, a lake to warm."""

    SOURCE_FAILED = "source_failed"
    """A source could not be reached. Coverage for this run is incomplete."""

    LIMIT = "limit"
    """A budget or cap stopped the work early. Never silent."""


#: Order the reader should meet them in: what you must act on, then what
#: qualifies the run, then chores, then plain answers.
KIND_ORDER = [NoteKind.LIMIT, NoteKind.SOURCE_FAILED, NoteKind.NOT_CONFIGURED, NoteKind.RESULT]

KIND_LABEL = {
    NoteKind.LIMIT: "Stopped early",
    NoteKind.SOURCE_FAILED: "Could not be checked",
    NoteKind.NOT_CONFIGURED: "Not set up yet",
    NoteKind.RESULT: "Checked",
}

KIND_BLURB = {
    NoteKind.LIMIT: "the run hit a cap, so this is partial",
    NoteKind.SOURCE_FAILED: "unknown, not clean",
    NoteKind.NOT_CONFIGURED: "one-time setup would fix these",
    NoteKind.RESULT: "looked, nothing to report",
}

# Ordered because the first match wins and the patterns overlap: "never synced
# into this lake (run `umbra abuse sync`)" is a chore even though it also
# contains the word "not".
_RULES: list[tuple[NoteKind, re.Pattern[str]]] = [
    # "budget" alone matched a per-collector timeout, which is a coverage gap
    # rather than the run hitting a cap — the reader reaction is different, so
    # the bucket must be. LIMIT is about the *run* stopping short.
    (NoteKind.LIMIT, re.compile(
        r"job wall-clock|max_entities|stopping early|cap reached|truncat", re.I)),
    (
        NoteKind.NOT_CONFIGURED,
        re.compile(
            r"skipped \(no |not loaded|never synced|no [A-Z_]*API_KEY|"
            r"run `umbra |not configured|no key\b",
            re.I,
        ),
    ),
    (
        NoteKind.SOURCE_FAILED,
        re.compile(
            r"\berror\b|unavailable|unreachable|timeout|timed out|SERVFAIL|"
            r"refused|HTTP [45]\d\d|could not|failed",
            re.I,
        ),
    ),
]

#: Remedies keyed by a fragment of the condition. Kept here rather than at each
#: call site so the same advice cannot drift between collectors.
_REMEDIES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"geoip", re.I), "umbra geoip sync"),
    (re.compile(r"abuse sync|urlhaus|threatfox|feodo.*never synced", re.I), "umbra abuse sync"),
    (re.compile(r"ct ingest|owned corpus", re.I), "umbra ct ingest"),
    (re.compile(r"ABUSEIPDB", re.I), "set UMBRA_ABUSEIPDB_API_KEY in .env"),
    (re.compile(r"HIBP|haveibeenpwned", re.I), "set UMBRA_HIBP_API_KEY in .env"),
]

# Subjects a note is *about*. Replaced with a placeholder so two notes that
# differ only by which domain they name collapse into one condition.
_SUBJECT_PATTERNS = [
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                        # IPv4
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),                       # email
    re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),               # hostname
]

_PLACEHOLDER = "\u2063SUBJ\u2063"


def classify(note: str) -> NoteKind:
    """Which of the four things is this line saying?"""
    for kind, pattern in _RULES:
        if pattern.search(note):
            return kind
    return NoteKind.RESULT


def remedy_for(note: str) -> str | None:
    for pattern, fix in _REMEDIES:
        if pattern.search(note):
            return fix
    return None


def _template(note: str) -> tuple[str, list[str]]:
    """Strip the subjects out of a note so the condition can be compared.

    "ct_lake: no certs for umbra-osint.com in the owned corpus" and the same
    line about gmail.com are one condition affecting two domains.
    """
    subjects: list[str] = []

    def take(m: re.Match[str]) -> str:
        subjects.append(m.group(0))
        return _PLACEHOLDER

    out = note
    for pattern in _SUBJECT_PATTERNS:
        out = pattern.sub(take, out)
    # Trailing counts and timings differ run to run without changing the point.
    out = re.sub(r"\b\d+(?:\.\d+)?s\b", "Ns", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out, subjects


@dataclass
class NoteGroup:
    """One condition, however many times it was hit."""

    kind: NoteKind
    message: str
    """The note as written, with one representative subject restored."""
    count: int = 1
    subjects: list[str] = field(default_factory=list)
    remedy: str | None = None
    #: The subjects seen on each occurrence, in order. Kept per-occurrence
    #: rather than as one flat list — see `detail`.
    occurrences: list[tuple[str, ...]] = field(default_factory=list)

    @property
    def detail(self) -> str:
        """Which of the operator's entities this condition actually affected.

        Only rendered when the occurrences differ from each other. A note that
        names the same URL every time it fires — "feodo_tracker ... for url
        https://feodotracker.abuse.ch/downloads/ipblocklist.json", four times —
        has no per-subject story to tell, and listing "feodotracker.abuse.ch,
        ipblocklist.json" underneath said nothing except that a filename looks
        like a hostname to a regex. ct_lake failing for umbra-osint.com and then
        for gmail.com is the case worth naming.
        """
        if len(set(self.occurrences)) <= 1:
            return ""
        # Drop the subjects common to every occurrence. In "crt.sh unavailable
        # for umbra-osint.com" and "... for gmail.com", crt.sh is the source
        # that failed — it is in both, so it identifies nothing. The domains
        # are what differ, and they are what the reader needs.
        constant = set(self.occurrences[0]).intersection(*map(set, self.occurrences[1:]))
        uniq = [x for x in OrderedDict.fromkeys(self.subjects) if x not in constant]
        if len(uniq) <= 1:
            return ""
        shown = ", ".join(uniq[:3])
        # Never a silent cap: if the list is trimmed, say by how much.
        if len(uniq) > 3:
            shown += f", and {len(uniq) - 3} more"
        return shown


def summarize(notes: list[str]) -> list[NoteGroup]:
    """Collapse raw note strings into distinct, classified conditions.

    Order is stable: kind first (see KIND_ORDER), then most-repeated, then the
    order the run produced them. Stable output matters because these end up in
    a case export that people diff.
    """
    groups: OrderedDict[str, NoteGroup] = OrderedDict()

    for raw in notes:
        note = (raw or "").strip()
        if not note:
            continue
        # A multi-line exception dump is one condition; the first line carries
        # it and the rest is a stack trace nobody asked for.
        head = note.split("\n", 1)[0].strip()
        template, subjects = _template(head)
        existing = groups.get(template)
        if existing:
            existing.count += 1
            existing.subjects.extend(subjects)
            existing.occurrences.append(tuple(subjects))
            continue
        groups[template] = NoteGroup(
            kind=classify(head),
            message=head,
            count=1,
            subjects=list(subjects),
            remedy=remedy_for(head),
            occurrences=[tuple(subjects)],
        )

    ordered = sorted(
        groups.values(),
        key=lambda g: (KIND_ORDER.index(g.kind), -g.count),
    )
    return ordered


def summarize_by_kind(notes: list[str]) -> "OrderedDict[NoteKind, list[NoteGroup]]":
    """`summarize`, bucketed for rendering. Empty kinds are omitted."""
    out: OrderedDict[NoteKind, list[NoteGroup]] = OrderedDict()
    for group in summarize(notes):
        out.setdefault(group.kind, []).append(group)
    return out


def describe_http_failure(source: str, exc: Exception, url: str | None = None) -> str:
    """Say a source could not be reached without diagnosing the wrong thing.

    Umbra reported `feodo_tracker error: Server error '503 certificate has
    expired'`. abuse.ch's certificate was and is perfectly valid — that string
    is their Varnish reason phrase, interpolated straight from the exception
    into a line that reads like our own TLS validation failing. An operator who
    trusts that note goes and debugs a certificate problem that does not exist.

    A remote server's words are data, not a diagnosis. Report the status and
    the host; keep the raw text only where it cannot be mistaken for ours.
    """
    status = None
    response = getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(exc, "status_code", None)

    host = ""
    target = url or str(getattr(getattr(exc, "request", None), "url", "") or "")
    if target:
        m = re.match(r"https?://([^/]+)", target)
        if m:
            host = m.group(1)

    where = f" at {host}" if host else ""
    if status is not None:
        return (
            f"{source} unreachable{where} — the source returned HTTP {status}. "
            f"Not checked, so this is unknown rather than clean."
        )

    kind = type(exc).__name__
    return (
        f"{source} unreachable{where} — {kind}. "
        f"Not checked, so this is unknown rather than clean."
    )
