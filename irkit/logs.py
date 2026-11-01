
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
    timeline: list = field(default_factory=list)


def analyze_auth_log(lines, threshold: int = 5):
    """Analyze sshd log lines; return a list of Finding objects."""

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failures = defaultdict(list)
    successes = defaultdict(list)

    for line_number, line in enumerate(lines):
        m = FAILED.match(line)

        if m:
            failures[m["ip"]].append(
                (line_number, m["ts"], m["user"])
            )
            continue

        m = ACCEPTED.match(line)

        if m:
            successes[m["ip"]].append(
                (line_number, m["ts"], m["user"], m["method"])
            )

    findings = []

    for ip, events in failures.items():

        if len(events) < threshold:
            continue

        users = sorted({user for _, _, user in events})

        later_successes = [
            event
            for event in successes.get(ip, [])
            if event[0] > events[threshold - 1][0]
        ]

        if later_successes:
            first_ok = later_successes[0]

            timeline = [
                {
                    "time": ts,
                    "event": f"Failed login for {user}",
                    "source": ip
                }
                for _, ts, user in events
            ]

            timeline.append({
                "time": first_ok[1],
                "event": (
                    f"Successful login for {first_ok[2]} "
                    f"via {first_ok[3]}"
                ),
                "source": ip
            })

            findings.append(Finding(
                "critical",
                "Successful login after repeated failures",
                f"{ip} had {len(events)} failed attempts "
                f"({events[0][1]} to {events[-1][1]}) "
                f"then logged in as '{first_ok[2]}' "
                f"via {first_ok[3]} at {first_ok[1]}. "
                "Treat the account as potentially compromised.",
                ip,
                users,
                timeline
            ))

        else:
            kind = (
                "Password spraying"
                if len(users) >= 3
                else "Brute force"
            )

            timeline = [
                {
                    "time": ts,
                    "event": f"Failed login for {user}",
                    "source": ip
                }
                for _, ts, user in events
            ]

            findings.append(Finding(
                "high" if len(events) >= threshold * 4 else "medium",
                f"{kind} attempt",
                f"{ip} had {len(events)} failed attempts against "
                f"{len(users)} account(s): "
                f"{', '.join(users[:8])}"
                f"{'...' if len(users) > 8 else ''}.",
                ip,
                users,
                timeline
            ))

    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3
    }

    return sorted(findings, key=lambda f: order[f.severity])
