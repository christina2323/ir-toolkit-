"""Generate a Markdown incident report."""
from datetime import datetime, timezone
from .ioc import defang


def build_report(title, severity, findings, iocs, analyst="", summary=""):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        f"# Incident Report: {title}", "",
        f"- **Severity:** {severity.upper()}",
        f"- **Generated:** {now}",
        f"- **Analyst:** {analyst or 'unassigned'}", "",
        "## Summary", "", summary or "_Add a short, plain-language summary of what happened._", "",
        "## Findings", "",
    ]
    if findings:
        for i, f in enumerate(findings, 1):
            out += [f"{i}. **[{f.severity.upper()}] {f.title}** - {f.detail}"]
    else:
        out.append("No findings from automated analysis.")
    out += ["", "## Indicators of Compromise (defanged)", ""]
    if iocs:
        for kind, values in iocs.items():
            out.append(f"**{kind}**")
            out += [f"- `{defang(v)}`" for v in values]
            out.append("")
    else:
        out += ["None extracted.", ""]
    out += [
        "## Timeline", "", "| Time (UTC) | Event | Source |", "|---|---|---|", "| | | |", "",
        "## Containment / Eradication / Recovery", "",
        "- [ ] Containment actions", "- [ ] Eradication actions", "- [ ] Recovery and validation", "",
        "## Lessons Learned", "", "_What worked, what didn't, what changes?_", "",
    ]
    return "\n".join(out)
