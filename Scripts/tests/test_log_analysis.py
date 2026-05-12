from log_analysis import analyze_access_lines, generate_markdown_report


def make_line(hour: int, ip: str = "10.0.0.1", path: str = "/", status: int = 200) -> str:
    return (
        f'{ip} - - [10/May/2026:{hour:02d}:00:00 -0500] '
        f'"GET {path} HTTP/1.1" {status} 1234'
    )


def test_analyze_access_lines_detects_attacks_and_anomaly() -> None:
    lines = []
    for hour in range(23):
        lines.extend(make_line(hour) for _ in range(10))
    lines.extend(make_line(23, "185.220.101.5", "/?id=1' UNION SELECT 1,2,3--") for _ in range(100))
    lines.append(make_line(22, "45.33.32.156", "/admin/../../../etc/passwd", 403))
    lines.append(make_line(22, "45.33.32.156", "/search?q=<script>alert(1)</script>", 403))
    lines.append(make_line(22, "45.33.32.156", "/cgi-bin/test.cgi?cmd=id", 500))
    lines.append(make_line(22, "45.33.32.156", "/wp-admin/", 404))

    result = analyze_access_lines(lines)
    categories = {
        category
        for item in result["suspicious_requests"]
        for category in item["categories"]
    }

    assert {
        "sql_injection",
        "path_traversal",
        "xss",
        "command_injection",
        "wordpress_probe",
    }.issubset(categories)
    assert result["top_ips"][0] == {"ip": "10.0.0.1", "requests": 230}
    assert result["status_distribution"]["200"] == 330
    assert result["anomalies"][0]["hour"] == "2026-05-10 23:00"


def test_generate_markdown_report_contains_anomaly_section() -> None:
    analysis = analyze_access_lines([make_line(hour) for hour in range(2)])

    report = generate_markdown_report(analysis)

    assert "## Hourly Anomalies" in report
