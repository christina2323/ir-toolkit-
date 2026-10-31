"""SSH auth log analysis: brute force and suspected-compromise detection."""
import re
from collections import defaultdict
from dataclasses import dataclass, field

FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+Failed (?:password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+Accepted (?P<method>\w+) for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    ip: str = ""
    users: list = field(default_factory=list)


def analyze_auth_log(lines, threshold: int = 5):
    """Analyze sshd log lines; return a list of Finding objects."""
    failures = defaultdict(list)   # ip -> [(ts, user)]
    successes = defaultdict(list)  # ip -> [(ts, user, method)]

    for line in lines:
        m = FAILED.match(line)
        if m:
            failures[m["ip"]].append((m["ts"], m["user"]))
            continue
        m = ACCEPTED.match(line)
        if m:
            successes[m["ip"]].append((m["ts"], m["user"], m["method"]))

    findings = []
    for ip, events in failures.items():
        if len(events) < threshold:
            continue
        users = sorted({u for _, u in events})
        succeeded = successes.get(ip)
        if succeeded:
            first_ok = succeeded[0]
            findings.append(Finding(
                "critical",
                "Successful login after repeated failures",
                f"{ip} had {len(events)} failed attempts ({events[0][0]} to {events[-1][0]}) "
                f"then logged in as '{first_ok[1]}' via {first_ok[2]} at {first_ok[0]}. "
                "Treat the account as compromised.",
                ip, users))
        else:
            kind = "Password spraying" if len(users) >= 3 else "Brute force"
            findings.append(Finding(
                "high" if len(events) >= threshold * 4 else "medium",
                f"{kind} attempt",
                f"{ip} had {len(events)} failed attempts against {len(users)} account(s): "
                f"{', '.join(users[:8])}{'...' if len(users) > 8 else ''}.",
                ip, users))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: order[f.severity])
