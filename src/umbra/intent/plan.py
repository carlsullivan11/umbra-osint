"""Build IntentPlan from text — Phase I deterministic + Phase II LLM merge."""

from __future__ import annotations

import logging
import re
from typing import Iterable

from umbra.collectors.base import default_registry
from umbra.core.config import Settings, get_settings
from umbra.core.models import EntityType
from umbra.intent.extract import extract_flags, extract_hits, hits_to_seeds
from umbra.intent.merge import merge_flags, merge_seeds
from umbra.intent.schema import AnalyzeRequest, IntentFlags, IntentPlan, IntentSeed

log = logging.getLogger("umbra.intent.plan")

# Ordered collector bundles
_DOMAIN_CORE = [
    "dns_resolve",
    "dns_email_auth",
    "rdap_domain",
    "http_probe",
    "tech_fingerprint",
    # consumes the technology entities tech_fingerprint produces
    "cve_lookup",
    "tls_cert",
    # tls_cert and ct_lake both write fingerprint_sha1 onto the cert entity for
    # exactly this join. Without sslbl_cert here the abuse.ch SSL Blacklist lake
    # only ever ran under `umbra playbook` — prod had 2,195 cert entities and
    # zero sslbl_cert evidence rows. Offline lake read, so it costs no request.
    "sslbl_cert",
    # Owned corpus first, then the network. crt.sh is the flakiest dependency
    # Umbra has (502s under load) and it rate-limits; the lake is local and
    # survives the interactive trim that drops crtsh (C3).
    "ct_lake",
    "crtsh",
    "security_txt",
    "html_links",
    # After the owned and cheap sources, never before them. This is a
    # rate-limited third-party API, and DNS/TLS/the lakes are why the run
    # exists — they must not queue behind someone else's quota.
    "urlscan_io",
    # A stranger on /reputation got this and a full investigation did not.
    "domain_reputation",
    # Last on purpose. A cached ransomware.live GET is the least essential
    # thing here, and DNS and TLS are the reason the run exists — they must not
    # queue behind a third-party feed having a bad day.
    "ransomware_exposure",
]
_IP_CORE = [
    "rdap_ip", "asn_cymru", "ip_geo", "ip_reputation", "malware_infra",
    # Last, and after malware_infra: it is a third-party index read, so the
    # owned lakes and the registries answer first. Reading Shodan's index is
    # not `umbra scan ports` and carries none of that command's authorization
    # gate — see docs/INTERNETDB.md.
    "internetdb",
]
# email_profile first: it is offline and free, and what it says about the
# address (role account, disposable, delivery form) frames everything after it.
_EMAIL_CORE = ["email_profile", "email_split", "gravatar"]
_GH = ["github_user", "github_commits"]
_USER = ["username_presence"]
# opencorporates is deliberately absent. 31 evidence rows on production,
# every one a captcha wall — it has never returned data. OpenCorporates
# challenges datacenter IPs and the deployment is one, so the failure is
# structural, not a bad week. Still registered and selectable by name for
# CLI users on residential connections; just not worth a request here.
_ORG = ["wikidata", "edgar_search", "public_records_portals"]
# people_lake first: it is offline and free, and what Umbra already owns
# should answer before anything reaches out. 2.25M FEC contributors were
# reachable from no collector at all, so a person search returned 18 portal
# links and an EDGAR miss while the corpus sat one call away.
_PERSON = ["people_lake", "public_records_portals", "county_records", "wifi_maps", "sex_offender_registry", "animal_registry", "inmate_locator", "obituary_search", "court_records", "ddg_search", "wikidata", "edgar_search"]

_REFUSE_RE = re.compile(
    r"(?i)\b("
    r"find\s+(?:my\s+)?ex\b|dox(?:x|ing)?\b|stalk\b|swat\b|"
    r"home\s+address\s+of\b|where\s+does\s+she\s+live\b|where\s+does\s+he\s+live\b|"
    r"her\s+ssn\b|his\s+ssn\b|social\s+security\s+number\b"
    r")\b"
)


def select_collectors(
    seeds: Iterable[IntentSeed],
    flags: IntentFlags,
    *,
    registered: set[str] | None = None,
) -> list[str]:
    reg = registered if registered is not None else {c.name for c in default_registry().list()}
    out: list[str] = []
    seen: set[str] = set()

    def add_many(names: list[str]) -> None:
        for n in names:
            if n in reg and n not in seen:
                seen.add(n)
                out.append(n)

    types = {s.type for s in seeds if s.include}
    values = [s for s in seeds if s.include]

    if EntityType.DOMAIN in types or EntityType.URL in types:
        add_many(_DOMAIN_CORE)
        # DNS/HTML pivots produce IPs — run the passive IP set so Phase B
        # coverage does not wait on the daily backfill timer.
        add_many(_IP_CORE)
    if EntityType.URL in types:
        # Explicit as well as via _DOMAIN_CORE. Someone pasting a URL is asking
        # "what is this", and an existing public scan is the cheapest real
        # answer available without opening a connection to the target — so it
        # survives any later trim of the domain bundle. add_many dedupes.
        add_many(["urlscan_io"])
    if EntityType.IP in types:
        add_many(_IP_CORE)
    if EntityType.EMAIL in types:
        add_many(_EMAIL_CORE)
        add_many(["dns_resolve", "rdap_domain"])
    if any(s.type == EntityType.USERNAME and s.value.startswith("github:") for s in values):
        add_many(_GH)
    if EntityType.USERNAME in types:
        if flags.aggressive_username_probe or any(
            not s.value.startswith("github:") for s in values if s.type == EntityType.USERNAME
        ):
            add_many(_USER)
    if EntityType.LOCATION in types:
        add_many(["wifi_maps", "wikidata"])
    if EntityType.MAC in types:
        add_many(["mac_oui", "wifi_maps"])
    if EntityType.PHONE in types:
        # Offline validate only (Phase A). Community / FTC / carrier come later.
        add_many(["phone_validate"])
    if EntityType.CRYPTO_ADDRESS in types:
        add_many(["crypto_screen"])
    if EntityType.AIRCRAFT in types:
        # The owned FAA registry lake, and only that. No ADS-B, no commercial
        # flight-tracking API: this answers "who holds the registration", which
        # is a records question, not a where-is-it-now question.
        add_many(["faa_registry"])
    if EntityType.ORG in types or flags.want_corp_records:
        add_many(_ORG)
    if EntityType.PERSON in types:
        add_many(_PERSON)
    if flags.want_lookalikes:
        add_many(["lookalike_domains"])
    if flags.want_breaches:
        add_many(["hibp_breach"])
    if flags.want_web_search:
        add_many(["ddg_search"])
    if flags.want_wayback:
        add_many(["wayback_cdx"])

    # The web-search fallback exists for seeds nothing else handles. MAC,
    # phone, crypto and aircraft are offline table reads, so those plans must
    # not quietly become a person web-search. An N-number did exactly that
    # before it had a type: it fell through to the bare-org guess and the
    # "investigation" was a DuckDuckGo query for the string.
    if not out and values and not types.issubset(
        {EntityType.MAC, EntityType.PHONE, EntityType.CRYPTO_ADDRESS,
         EntityType.AIRCRAFT}
    ):
        add_many(["ddg_search"])

    return out


def infer_playbook(seeds: list[IntentSeed], flags: IntentFlags) -> str:
    types = {s.type for s in seeds if s.include}
    if types and types.issubset({EntityType.CRYPTO_ADDRESS}):
        return "crypto_screen"
    if types and types.issubset({EntityType.PHONE}):
        return "phone_reputation"
    if EntityType.PERSON in types or (
        EntityType.USERNAME in types and EntityType.DOMAIN in types
    ):
        return "person_footprint"
    if EntityType.DOMAIN in types or EntityType.URL in types:
        return "domain_dossier"
    if EntityType.EMAIL in types:
        return "person_footprint"
    return "custom"


def infer_case_name(seeds: list[IntentSeed], text: str) -> str:
    for t in (
        EntityType.DOMAIN,
        EntityType.PHONE,
        EntityType.CRYPTO_ADDRESS,
        EntityType.PERSON,
        EntityType.ORG,
        EntityType.EMAIL,
    ):
        for s in seeds:
            if s.include and s.type == t:
                return f"Intent:{s.value}"[:80]
    snippet = re.sub(r"\s+", " ", text.strip())[:40]
    return f"Intent:{snippet or 'untitled'}"


def summarize(seeds: list[IntentSeed], flags: IntentFlags) -> str:
    inc = [s for s in seeds if s.include]
    parts = [f"{len(inc)} seed(s)"]
    by_t: dict[str, int] = {}
    for s in inc:
        by_t[s.type.value] = by_t.get(s.type.value, 0) + 1
    if by_t:
        parts.append(", ".join(f"{k}={v}" for k, v in sorted(by_t.items())))
    flag_on = [k for k, v in flags.model_dump().items() if v]
    if flag_on:
        parts.append("flags: " + ", ".join(flag_on))
    return "; ".join(parts)


def _should_use_llm(req: AnalyzeRequest, settings: Settings) -> bool:
    if req.use_llm is False:
        return False
    if req.use_llm is True:
        return settings.llm_configured
    # auto
    return bool(settings.llm_enabled and settings.llm_configured)


def analyze_intent(
    req: AnalyzeRequest,
    settings: Settings | None = None,
) -> IntentPlan:
    settings = settings or get_settings()
    text = (req.text or "").strip()
    plan = IntentPlan(
        authorization_basis=req.authorization_basis,
        authorization_note=req.authorization_note or "",
        depth=max(0, min(3, req.default_depth)),
        max_entities=req.max_entities,
        raw_intent=text,
        extractor="deterministic_v1",
    )

    if not text:
        plan.warnings.append("Empty intent text")
        plan.clarifying_questions.append("Paste domains, emails, usernames, or notes to analyze.")
        return plan

    # Soft refuse — still return plan for transparency
    if _REFUSE_RE.search(text) and req.authorization_basis in {"training_lab", "other"}:
        plan.refuse = True
        plan.refuse_reason = (
            "Intent looks like non-authorized personal targeting. "
            "Use own_asset or client_engagement with a clear authorization note, "
            "or rephrase around assets you own / are contracted to assess."
        )
        plan.warnings.append(plan.refuse_reason)

    flags = extract_flags(text)
    hits = extract_hits(text)
    seeds = hits_to_seeds(hits)
    extractor_label = "deterministic_v1"

    # --- Phase II: optional LLM enrich + merge ---
    if _should_use_llm(req, settings):
        try:
            from umbra.intent.llm import llm_enrich

            llm_part = llm_enrich(
                settings,
                text=text,
                basis=req.authorization_basis,
                note=req.authorization_note or "",
                deterministic_seeds=seeds,
                deterministic_flags=flags,
            )
            seeds = merge_seeds(seeds, llm_part["seeds"])
            flags = merge_flags(flags, llm_part["flags"])
            if llm_part.get("warnings"):
                plan.warnings.extend(llm_part["warnings"])
            if llm_part.get("clarifying_questions"):
                plan.clarifying_questions.extend(llm_part["clarifying_questions"])
            if llm_part.get("refuse"):
                plan.refuse = True
                plan.refuse_reason = llm_part.get("refuse_reason") or plan.refuse_reason
                if plan.refuse_reason:
                    plan.warnings.append(plan.refuse_reason)
            if llm_part.get("case_name") and not req.case_name:
                plan.case_name = str(llm_part["case_name"])[:120]
            if llm_part.get("summary"):
                plan.summary = str(llm_part["summary"])[:500]
            extractor_label = "deterministic_v1+llm"
        except Exception as exc:  # noqa: BLE001
            log.warning("LLM intent enrich failed: %s", exc)
            plan.warnings.append(f"LLM enrich failed — using deterministic only: {exc}")
            extractor_label = "deterministic_v1(llm_failed)"
    elif req.use_llm is True and not settings.llm_configured:
        plan.warnings.append(
            "LLM requested but not configured. Set UMBRA_LLM_BASE_URL and UMBRA_LLM_MODEL."
        )

    # Validation warnings
    if flags.want_lookalikes and not any(s.type == EntityType.DOMAIN and s.include for s in seeds):
        plan.warnings.append("Lookalikes requested but no domain seed found")

    if flags.want_breaches and not any(s.type == EntityType.EMAIL and s.include for s in seeds):
        plan.warnings.append("Breaches requested but no email seed found — hibp_breach needs emails")

    plan.flags = flags
    plan.seeds = seeds
    plan.collectors = select_collectors(seeds, flags)
    plan.playbook = infer_playbook(seeds, flags)
    if any(s.include and s.type == EntityType.CRYPTO_ADDRESS for s in seeds):
        plan.warnings.append(
            "Crypto address screening is the owned label lake — "
            "use /crypto or `umbra crypto screen` (not web-search)."
        )
    if any(s.include and s.type == EntityType.PERSON for s in seeds):
        plan.warnings.append(
            "Person seeds run obituary/portals collectors. Instant lake lookup: "
            "/people or `umbra people lookup`."
        )
    if not plan.case_name or plan.case_name == "Intent case":
        plan.case_name = (req.case_name or infer_case_name(seeds, text))[:120]
    elif req.case_name:
        plan.case_name = req.case_name[:120]
    if not plan.summary:
        plan.summary = summarize(seeds, flags)
    else:
        # append seed stats for operator clarity
        plan.summary = f"{plan.summary} · {summarize(seeds, flags)}"
    plan.extractor = extractor_label

    if not any(s.include for s in seeds):
        plan.warnings.append("No high-confidence seeds — edit plan or add identifiers")
        plan.clarifying_questions.append(
            "Include an email, domain, IP, URL, person: Full Name, crypto address, or platform handle (e.g. github:user)."
        )

    low = [s for s in seeds if not s.include]
    if low:
        plan.warnings.append(
            f"{len(low)} low-confidence seed(s) excluded by default (opt in to include)"
        )

    # de-dupe warnings / questions
    plan.warnings = list(dict.fromkeys(plan.warnings))
    plan.clarifying_questions = list(dict.fromkeys(plan.clarifying_questions))

    return plan
