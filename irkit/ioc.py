"""Indicator-of-compromise (IOC) extraction and defanging."""
import re
from ipaddress import ip_address

PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"']+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I),
}

# Domains that appear as part of URLs/emails are reported under those types only
_FILE_EXT_FALSE_POSITIVES = {"exe", "dll", "txt", "log", "py", "sh", "bat", "zip", "doc", "docx", "pdf", "png", "jpg"}


def extract_iocs(text: str) -> dict:
    """Return a dict of IOC type -> sorted unique values found in text."""
    found = {}
    for name, pattern in PATTERNS.items():
        matches = set(m.group(0) for m in pattern.finditer(text))
        found[name] = matches

    # Remove hashes that are substrings of longer hashes
    found["sha1"] -= {h for h in found["sha1"] if any(h in s for s in found["sha256"])}
    found["md5"] -= {h for h in found["md5"] if any(h in s for s in found["sha1"] | found["sha256"])}

    # Domains: drop anything already covered by URLs/emails, IPs, or file names
    covered = set()
    for u in found["url"]:
        covered.add(re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0].lower())
    for e in found["email"]:
        covered.add(e.split("@")[1].lower())
    found["domain"] = {
        d for d in found["domain"]
        if d.lower() not in covered
        and d.rsplit(".", 1)[-1].lower() not in _FILE_EXT_FALSE_POSITIVES
        and not PATTERNS["ipv4"].fullmatch(d)
    }
    found["cve"] = {c.upper() for c in found["cve"]}
    return {k: sorted(v) for k, v in found.items() if v}


def is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def defang(value: str) -> str:
    """Make an indicator safe to paste in tickets/chat (hxxp://example[.]com)."""
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    value = value.replace("@", "[@]")
    return value.replace(".", "[.]")
