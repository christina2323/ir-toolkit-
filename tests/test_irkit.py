from pathlib import Path
from irkit.ioc import extract_iocs, defang
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
