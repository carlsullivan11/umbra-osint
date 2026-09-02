"""Human-readable breach remediation reports."""

from __future__ import annotations

from umbra.collectors.hibp_breach import remediation_for_data_classes, severity_for_breach
from umbra.core.models import CollectorResult, EntityType


def render_breach_report(email: str, result: CollectorResult) -> str:
    breaches = [e for e in result.entities if e.type == EntityType.BREACH]
    lines: list[str] = []
    lines.append(f"**Account:** `{email}`")
    lines.append(f"**Breaches found:** {len(breaches)}")
    lines.append("")

    if not breaches:
        if any("API key" in n or "missing_api_key" in n for n in result.notes):
            lines.append("Lookup was not completed (API key missing or error).")
            lines.append("Set `UMBRA_HIBP_API_KEY` and re-run `umbra breach email`.")
        else:
            lines.append("No breaches returned for this email in Have I Been Pwned.")
            lines.append("Still recommended: unique passwords, MFA on email, phishing vigilance.")
        return "\n".join(lines)

    # Aggregate remediation
    all_classes: list[str] = []
    high = med = low = 0
    for b in breaches:
        props = b.props or {}
        sev = props.get("severity") or "low"
        if sev == "high":
            high += 1
        elif sev == "medium":
            med += 1
        else:
            low += 1
        all_classes.extend(props.get("data_classes") or [])

    lines.append(f"**Severity mix:** high={high}, medium={med}, low={low}")
    lines.append("")
    lines.append("## Priority actions")
    for i, step in enumerate(remediation_for_data_classes(all_classes)[:15], 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Per-breach detail")
    for b in sorted(breaches, key=lambda x: (x.props or {}).get("breach_date") or "", reverse=True):
        props = b.props or {}
        lines.append(f"### {props.get('title') or b.value}")
        lines.append(f"- **Date:** {props.get('breach_date', '?')}")
        lines.append(f"- **Severity:** {props.get('severity', '?')}")
        lines.append(f"- **Pwn count (total in breach):** {props.get('pwn_count', '?')}")
        classes = props.get("data_classes") or []
        if classes:
            lines.append(f"- **Data classes:** {', '.join(classes)}")
        lines.append("- **Do this:**")
        for step in (props.get("remediation") or remediation_for_data_classes(classes))[:5]:
            lines.append(f"  - {step}")
        lines.append("")

    lines.append("## Hardening checklist (always)")
    lines.append("- [ ] Password manager with unique passwords")
    lines.append("- [ ] MFA on email (this is the crown jewel)")
    lines.append("- [ ] MFA on banking, cloud, password manager, work SSO")
    lines.append("- [ ] Review forwarding rules / app passwords on email")
    lines.append("- [ ] Remove unused accounts from old breaches")
    lines.append("- [ ] Credit freeze if SSN/financial data was in any breach")
    lines.append("")
    lines.append("_Source: Have I Been Pwned API. Authorized monitoring only._")
    return "\n".join(lines)


def append_breach_section_to_profile(md: str, result_blocks: list[str]) -> str:
    if not result_blocks:
        return md
    extra = ["", "## Breach exposure & remediation", ""] + result_blocks
    return md.rstrip() + "\n" + "\n".join(extra) + "\n"
