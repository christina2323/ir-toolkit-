"""Command line interface: python -m irkit <command>."""
import argparse
import json
import sys
from pathlib import Path

from .ioc import extract_iocs, defang
from .logs import analyze_auth_log
from .report import build_report

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"


def _read(path):
    return Path(path).read_text(errors="replace")


def cmd_logs(a):
    findings = analyze_auth_log(_read(a.file).splitlines(), a.threshold)
    if a.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    elif not findings:
        print("No suspicious activity found.")
    else:
        for f in findings:
            print(f"[{f.severity.upper():8}] {f.title}\n           {f.detail}\n")
    return 2 if any(f.severity in ("critical", "high") for f in findings) else 0


def cmd_iocs(a):
    iocs = extract_iocs(_read(a.file))
    if a.json:
        print(json.dumps(iocs, indent=2))
        return 0
    for kind, values in iocs.items():
        print(f"{kind} ({len(values)})")
        for v in values:
            print(f"  {defang(v) if a.defang else v}")
    return 0


def cmd_report(a):
    findings = analyze_auth_log(_read(a.logs).splitlines(), a.threshold) if a.logs else []
    iocs = extract_iocs(_read(a.iocs_from)) if a.iocs_from else {}
    text = build_report(a.title, a.severity, findings, iocs, a.analyst, a.summary)
    if a.output:
        Path(a.output).write_text(text)
        print(f"Report written to {a.output}")
    else:
        print(text)
    return 0


def cmd_playbook(a):
    books = sorted(PLAYBOOK_DIR.glob("*.md"))
    if a.name is None:
        for b in books:
            print(b.stem)
        return 0
    match = PLAYBOOK_DIR / f"{a.name}.md"
    if not match.exists():
        print(f"Unknown playbook '{a.name}'. Available: {', '.join(b.stem for b in books)}", file=sys.stderr)
        return 1
    print(match.read_text())
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="irkit", description="Incident response toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("logs", help="analyze an sshd auth log")
    s.add_argument("file"); s.add_argument("--threshold", type=int, default=5)
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_logs)

    s = sub.add_parser("iocs", help="extract IOCs from any text file")
    s.add_argument("file"); s.add_argument("--defang", action="store_true")
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_iocs)

    s = sub.add_parser("report", help="generate a Markdown incident report")
    s.add_argument("--title", required=True)
    s.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    s.add_argument("--logs"); s.add_argument("--iocs-from"); s.add_argument("--threshold", type=int, default=5)
    s.add_argument("--analyst", default=""); s.add_argument("--summary", default="")
    s.add_argument("-o", "--output"); s.set_defaults(fn=cmd_report)

    s = sub.add_parser("playbook", help="list or show response playbooks")
    s.add_argument("name", nargs="?"); s.set_defaults(fn=cmd_playbook)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
