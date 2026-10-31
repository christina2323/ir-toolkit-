# irkit - Incident Response Toolkit

A small, dependency-free Python toolkit for the first hours of a security incident.

![tests](../../actions/workflows/ci.yml/badge.svg)

## What it does

| Command | Purpose |
|---|---|
| `irkit logs <auth.log>` | Detect SSH brute force, password spraying, and **successful logins after repeated failures** |
| `irkit iocs <file> [--defang]` | Extract IPs, domains, URLs, emails, hashes, CVEs from any text |
| `irkit report --title ...` | Generate a Markdown incident report (findings, IOCs, timeline, lessons learned) |
| `irkit playbook [name]` | Show response checklists: phishing, ransomware, account compromise |

## Quick start

```bash
git clone https://github.com/christina2323/ir-toolkit && cd ir-toolkit
python -m irkit logs samples/auth.log
python -m irkit iocs samples/phishing_email.txt --defang
python -m irkit report --title "SSH compromise on web01" --severity high \
    --logs samples/auth.log --iocs-from samples/phishing_email.txt -o reports/web01.md
python -m irkit playbook ransomware
```

`irkit logs` exits with code 2 on high/critical findings, so it can gate scripts or cron alerts.

## Tests

```bash
pip install pytest && pytest
```

## Roadmap
- Windows event log (EVTX/CSV) support
- Web server log analysis (SQLi / scanner patterns)
- Enrichment via VirusTotal / AbuseIPDB (opt-in, API key)
- Timeline builder merging multiple log sources

## Disclaimer
For defensive use on systems you own or are authorized to investigate. Sample IPs use documentation ranges (RFC 5737).
