from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import networkx as nx

from umbra.db.repository import Repository
from umbra.db.schema import Entity


def build_networkx(repo: Repository, case_id: str) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    entities = repo.list_entities(case_id)
    id_to_ent = {e.id: e for e in entities}
    for e in entities:
        g.add_node(
            e.id,
            type=e.type,
            value=e.value,
            norm_key=e.norm_key,
            is_seed=e.is_seed,
            confidence=e.confidence,
            label=f"{e.type}:{e.value}",
        )
    for edge in repo.list_edges(case_id):
        if edge.source_id in id_to_ent and edge.target_id in id_to_ent:
            g.add_edge(
                edge.source_id,
                edge.target_id,
                key=edge.rel,
                rel=edge.rel,
                confidence=edge.confidence,
            )
    return g


def export_graphml(repo: Repository, case_id: str, path: Path) -> Path:
    g = build_networkx(repo, case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    for _, data in g.nodes(data=True):
        for k, v in list(data.items()):
            if isinstance(v, bool):
                data[k] = str(v)
    nx.write_graphml(g, path)
    return path


def render_profile_markdown(repo: Repository, case_id: str, seed_value: str | None = None) -> str:
    case = repo.get_case(case_id)
    assert case
    entities = repo.list_entities(case_id)
    edges = repo.list_edges(case_id)
    evidence = repo.list_evidence(case_id)

    seeds = [e for e in entities if e.is_seed]
    if seed_value:
        focus = [e for e in entities if e.value == seed_value or e.norm_key.endswith(":" + seed_value)]
    else:
        focus = seeds or entities[:1]

    by_type: dict[str, list[Entity]] = defaultdict(list)
    for e in entities:
        by_type[e.type].append(e)

    id_map = {e.id: e for e in entities}
    lines: list[str] = []
    lines.append(f"# Subject Profile — {case.name}")
    lines.append("")
    lines.append(f"- **Case ID:** `{case.id}`")
    lines.append(f"- **Authorization:** `{case.authorization_basis}` — {case.authorization_note or 'n/a'}")
    lines.append(f"- **Entities:** {len(entities)} · **Edges:** {len(edges)} · **Evidence:** {len(evidence)}")

    bands = {"high": 0, "medium": 0, "low": 0, "speculative": 0}
    for e in entities:
        b = (e.props or {}).get("score_band")
        if not b:
            c = float(e.confidence or 0)
            b = "high" if c >= 0.85 else "medium" if c >= 0.6 else "low" if c >= 0.35 else "speculative"
        bands[b] = bands.get(b, 0) + 1
    lines.append(
        f"- **Confidence bands:** high={bands['high']} · medium={bands['medium']} · "
        f"low={bands['low']} · speculative={bands['speculative']}"
    )
    lines.append("")
    lines.append("## Seeds / Focus")
    for e in focus:
        band = (e.props or {}).get("score_band", "")
        extra = f", {band}" if band else ""
        lines.append(f"- `{e.type}` **{e.value}** (conf {e.confidence:.2f}{extra})")
    lines.append("")

    ranked = sorted(entities, key=lambda x: float(x.confidence or 0), reverse=True)
    high = [e for e in ranked if float(e.confidence or 0) >= 0.85][:25]
    weak = [e for e in ranked if float(e.confidence or 0) < 0.35 and not e.is_seed][:20]
    if high:
        lines.append("## High-confidence entities")
        for e in high:
            v = getattr(e, "verification", None) or "unknown"
            lines.append(f"- `{e.type}:{e.value}` — **{e.confidence:.2f}** (verify={v})")
        lines.append("")
    if weak:
        lines.append("## Speculative entities (review / verify)")
        for e in weak:
            lines.append(f"- `{e.type}:{e.value}` — {e.confidence:.2f}")
        lines.append("")
        lines.append("_Mark with `umbra entity verify <id> -s true|false` then `umbra score <case>`._")
        lines.append("")

    # Reputation verdicts (IP / domain) — worst first
    flagged = [
        e for e in entities
        if (e.props or {}).get("reputation_verdict") in ("malicious", "suspicious")
    ]
    if flagged:
        _order = {"malicious": 0, "suspicious": 1}
        flagged.sort(key=lambda e: (
            _order.get((e.props or {}).get("reputation_verdict"), 2),
            -int((e.props or {}).get("reputation_score", 0)),
        ))
        lines.append("## Reputation flags")
        lines.append(f"**{len(flagged)}** entity(ies) flagged by threat-intel sources.")
        lines.append("")
        for e in flagged[:40]:
            p = e.props or {}
            verdict = p.get("reputation_verdict")
            score = p.get("reputation_score", 0)
            srcs = ", ".join(p.get("reputation_sources") or []) or "—"
            badge = "🔴" if verdict == "malicious" else "🟠"
            lines.append(f"- {badge} `{e.type}:{e.value}` — **{verdict}** "
                         f"(score {score}) · sources: {srcs}")
        lines.append("")
        lines.append("_Verdicts aggregate public threat-intel; see evidence for per-source provenance._")
        lines.append("")

    # An entity the lookup could not check is not a clean entity. Omitting it
    # here reads as "checked and fine" — the DNSBL failure mode landing in an
    # audit artifact (docs/DNS-SERVICE.md).
    unchecked = [
        e for e in entities
        if (e.props or {}).get("reputation_verdict") in ("error", "unknown")
    ]
    if unchecked:
        lines.append("## Reputation — not checked")
        lines.append(
            f"**{len(unchecked)}** entity(ies) **could not be checked** — the "
            "reputation lookup errored. This is *not* a clean result; a DNSBL "
            "query through a misconfigured resolver returns errors for "
            "everything (see `docs/DNS-SERVICE.md`)."
        )
        lines.append("")
        for e in unchecked[:40]:
            lines.append(f"- ⚪ `{e.type}:{e.value}` — could not be checked")
        lines.append("")

    # Email authentication posture — spoofable domains first (actionable)
    mail_domains = [
        e for e in entities
        if (e.props or {}).get("email_posture_grade") is not None
    ]
    if mail_domains:
        _grade_order = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
        mail_domains.sort(key=lambda e: (
            not (e.props or {}).get("spoofable", False),          # spoofable first
            _grade_order.get((e.props or {}).get("email_posture_grade"), 9),
        ))
        spoofable_n = sum(1 for e in mail_domains if (e.props or {}).get("spoofable"))
        lines.append("## Email authentication posture")
        lines.append(
            f"**{len(mail_domains)}** domain(s) checked · "
            f"**{spoofable_n}** spoofable (no enforcing DMARC policy)."
        )
        lines.append("")
        for e in mail_domains[:40]:
            p = e.props or {}
            grade = p.get("email_posture_grade")
            badge = "🔴" if p.get("spoofable") else "🟢"
            dmarc = p.get("dmarc_policy") or "none"
            spf_all = ((p.get("spf_parsed") or {}) or {}).get("all") or "—"
            dkim = len(p.get("dkim_selectors") or [])
            extras = []
            if (p.get("mta_sts") or {}).get("mode"):
                extras.append(f"MTA-STS={p['mta_sts']['mode']}")
            if p.get("bimi"):
                extras.append("BIMI")
            if p.get("dnssec"):
                extras.append("DNSSEC")
            lines.append(
                f"- {badge} `{e.value}` — **{grade}** · DMARC `p={dmarc}` · "
                f"SPF all `{spf_all}` · DKIM selectors {dkim}"
                + (f" · {', '.join(extras)}" if extras else "")
            )
            for reason in (p.get("email_posture_reasons") or [])[:3]:
                lines.append(f"  - {reason}")
        lines.append("")
        if spoofable_n:
            lines.append(
                "_**Spoofable** = DMARC policy is not `quarantine`/`reject`, so receivers "
                "are not told to reject forged mail from this domain. Fix: publish SPF with "
                "`-all`/`~all`, sign with DKIM, then move DMARC to `p=quarantine` → `p=reject`._"
            )
            lines.append("")

    breaches = by_type.get("breach") or []
    if breaches:
        lines.append("## Breach exposure & remediation")
        lines.append(f"Found **{len(breaches)}** breach entity(ies) linked to this case.")
        lines.append("")
        def _breach_sort_key(x):
            p = x.props or {}
            return p.get("breach_date") or p.get("discovered") or ""

        for e in sorted(breaches, key=_breach_sort_key, reverse=True)[:40]:
            props = e.props or {}
            if props.get("kind") == "ransomware_leak":
                # Passive, defensive: report the fact + pointer, never a copy.
                title = props.get("victim") or e.display_name or e.value
                group = props.get("group") or "unknown group"
                lines.append(f"### 🔴 Ransomware leak — {title}")
                lines.append(
                    f"- **Group:** {group} · **Severity:** {props.get('severity', 'high')}"
                    f" · **Listed:** {(props.get('discovered') or '?')[:10]}"
                )
                if props.get("activity"):
                    lines.append(f"- **Sector:** {props.get('activity')}"
                                 + (f" · **Country:** {props.get('country')}" if props.get("country") else ""))
                lines.append(f"- **Source:** {props.get('source', 'ransomware.live')} "
                             "(public leak-site index — fact of exposure only, not the data)")
                lines.append("- **Actions:**")
                for step in (
                    "Confirm the posting against your own IR / SOC records",
                    "Assume data exfiltration; scope impacted systems and data",
                    "Rotate credentials and secrets for exposed systems",
                    "Notify legal/compliance and affected parties per obligations",
                ):
                    lines.append(f"  - {step}")
                lines.append("")
                continue
            title = props.get("title") or e.display_name or e.value
            lines.append(f"### {title}")
            lines.append(
                f"- **Severity:** {props.get('severity', '?')} · **Date:** {props.get('breach_date', '?')}"
            )
            classes = props.get("data_classes") or []
            if classes:
                lines.append(f"- **Data classes:** {', '.join(classes)}")
            remed = props.get("remediation") or []
            if remed:
                lines.append("- **Actions:**")
                for step in remed[:6]:
                    lines.append(f"  - {step}")
            lines.append("")
        for em in by_type.get("email") or []:
            prio = (em.props or {}).get("remediation_priority") or []
            if prio:
                lines.append(f"### Priority actions for `{em.value}`")
                for i, step in enumerate(prio[:10], 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
        lines.append(
            "_Password check (k-anonymity): `umbra breach password` · Email: `umbra breach email <addr>`_"
        )
        lines.append("")

    # Ransomware leak-site exposure — the single most actionable finding a
    # profile can carry, so it gets a heading rather than a row in evidence.
    leaks = [e for e in entities if (e.props or {}).get("kind") == "ransomware_leak"]
    if leaks:
        lines.append("## Ransomware exposure")
        lines.append(
            f"**{len(leaks)}** entity(ies) appear on a public ransomware leak "
            "site index. This is a *published claim by the operators of that "
            "site*, not a verified breach."
        )
        lines.append("")
        for e in leaks[:20]:
            p = e.props or {}
            group = p.get("group", "unknown group")
            published = p.get("published") or "date unknown"
            source = p.get("source", "ransomware.live")
            lines.append(f"- 🔴 `{e.type}:{e.value}` — claimed by **{group}** "
                         f"({published}, via {source})")
        lines.append("")

    lines.append("## Entity Inventory")
    for t in sorted(by_type.keys()):
        lines.append(f"### {t} ({len(by_type[t])})")
        for e in sorted(by_type[t], key=lambda x: (-float(x.confidence or 0), x.value))[:100]:
            seed_mark = " 🌱" if e.is_seed else ""
            band = (e.props or {}).get("score_band")
            band_s = f" [{band}]" if band else ""
            lines.append(f"- `{e.value}`{seed_mark} ({e.confidence:.2f}){band_s}")
        if len(by_type[t]) > 100:
            lines.append(f"- … +{len(by_type[t]) - 100} more")
        lines.append("")

    lines.append("## Relationships")
    for edge in edges[:200]:
        s = id_map.get(edge.source_id)
        t = id_map.get(edge.target_id)
        if not s or not t:
            continue
        lines.append(f"- `{s.type}:{s.value}` —**{edge.rel}**→ `{t.type}:{t.value}`")
    if len(edges) > 200:
        lines.append(f"- … +{len(edges) - 200} more edges")
    lines.append("")

    lines.append("## Evidence (recent)")
    for ev in evidence[:30]:
        lines.append(f"- **{ev.collector}** / {ev.source_name}: {ev.summary}")
        if ev.source_url:
            lines.append(f"  - {ev.source_url}")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by Umbra. Authorized use only._")
    return "\n".join(lines)


def write_profile(repo: Repository, case_id: str, path: Path, seed_value: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_profile_markdown(repo, case_id, seed_value), encoding="utf-8")
    return path
