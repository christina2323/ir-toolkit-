from pathlib import Path
from irkit.ioc import extract_iocs, defang, is_private_ip
from irkit.logs import analyze_auth_log

ROOT = Path(__file__).resolve().parent.parent


def test_ioc_extraction():
    iocs = extract_iocs((ROOT / "samples/phishing_email.txt").read_text())
    assert "198.51.100.77" in iocs["ipv4"]
    assert "CVE-2024-3400" in iocs["cve"]
    assert len(iocs["sha256"]) == 1
    assert "update.malware-cdn.example" in iocs["domain"]
    assert "md5" not in iocs and "sha1" not in iocs  # substrings of sha256 not double counted


def test_defang():
    assert defang("http://evil.example/x") == "hxxp://evil[.]example/x"


def test_log_findings():
    lines = (ROOT / "samples/auth.log").read_text().splitlines()
    findings = analyze_auth_log(lines, threshold=5)
    assert findings[0].severity == "critical" and findings[0].ip == "203.0.113.45"
    assert any(f.ip == "198.51.100.7" for f in findings)
    assert not any(f.ip == "192.0.2.10" for f in findings)


def test_threshold():
    lines = (ROOT / "samples/auth.log").read_text().splitlines()
    assert analyze_auth_log(lines, threshold=50) == []


def test_successful_login_after_repeated_failures():
    lines = [
        "Oct 31 02:14:01 host sshd[123]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:02 host sshd[123]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:03 host sshd[123]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:04 host sshd[123]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:05 host sshd[123]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:06 host sshd[123]: Accepted password for deploy from 203.0.113.45 port 5555 ssh2",
    ]

    findings = analyze_auth_log(lines, threshold=5)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].ip == "203.0.113.45"

    
def test_success_before_repeated_failures():
    lines = [
        "Oct 31 01:00:00 host sshd[100]: Accepted password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:01 host sshd[101]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:02 host sshd[102]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:03 host sshd[103]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:04 host sshd[104]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
        "Oct 31 02:14:05 host sshd[105]: Failed password for deploy from 203.0.113.45 port 5555 ssh2",
    ]

    findings = analyze_auth_log(lines, threshold=5)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].title == "Brute force attempt"

def test_is_private_ip():
    assert is_private_ip("192.168.1.10") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("not-an-ip") is False

def test_duplicate_ioc_removal():
    text = """
    Suspicious IP: 198.51.100.77
    Another mention: 198.51.100.77
    """

    iocs = extract_iocs(text)

    assert iocs["ipv4"] == ["198.51.100.77"]