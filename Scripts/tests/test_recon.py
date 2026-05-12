from recon import generate_report, missing_security_headers


def test_missing_security_headers_detects_absent_headers_case_insensitively() -> None:
    headers = {"content-security-policy": "default-src 'self'"}

    assert missing_security_headers(headers) == [
        "Strict-Transport-Security",
        "X-Frame-Options",
    ]


def test_generate_report_includes_domain_sections_and_errors() -> None:
    results = {
        "target": "example.test",
        "mode": "domain",
        "timestamp": "2026-05-11T12:00:00",
        "whois": {
            "success": False,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "registrant_organization": None,
            "error": "command not found: whois",
        },
        "dig": {
            "A": {"success": True, "records": ["127.0.0.1"], "error": None},
            "MX": {"success": True, "records": [], "error": None},
            "NS": {"success": True, "records": [], "error": None},
            "TXT": {"success": True, "records": [], "error": None},
        },
        "curl": {
            "success": True,
            "headers": {"Server": "nginx"},
            "missing_security_headers": [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
            ],
            "error": None,
        },
    }

    report = generate_report(results)

    assert "## DNS Records" in report
    assert "## Missing Security Headers" in report
    assert "command not found: whois" in report
