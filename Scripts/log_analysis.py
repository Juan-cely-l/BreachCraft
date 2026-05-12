"""Analyze web access logs for suspicious requests and traffic anomalies."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO


LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) (?P<protocol>HTTP/[0-9.]+)" '
    r"(?P<status>\d{3}) (?P<size>\S+)",
)

ATTACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "sql_injection",
        re.compile(
            r"(union(?:\s|%20|\+)+select|select(?:\s|%20|\+).+from|"
            r"drop(?:\s|%20|\+)+table|or(?:\s|%20|\+)+1=1|--|%27|')",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE),
    ),
    (
        "xss",
        re.compile(r"(<script|%3cscript|javascript:|onerror=|alert\()", re.IGNORECASE),
    ),
    (
        "command_injection",
        re.compile(
            r"([?&](cmd|exec|shell)=|/bin/(sh|bash)|;|\|\||&&|%7c|%26%26)",
            re.IGNORECASE,
        ),
    ),
    (
        "wordpress_probe",
        re.compile(r"(/wp-admin/?|/wp-login\.php|/xmlrpc\.php|/wp-content/)", re.IGNORECASE),
    ),
]


def parse_log_line(line: str) -> dict[str, str] | None:
    match = LOG_RE.search(line)
    if not match:
        return None
    return match.groupdict()


def attack_categories(path: str) -> list[str]:
    return [name for name, pattern in ATTACK_PATTERNS if pattern.search(path)]


def hour_bucket(timestamp: str) -> str | None:
    try:
        parsed = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        match = re.search(r":(?P<hour>\d{2}):\d{2}:\d{2}", timestamp)
        return f"{match.group('hour')}:00" if match else None

    return parsed.strftime("%Y-%m-%d %H:00")


def detect_anomalies(
    hourly_counts: Counter[str],
    threshold_sigma: float = 3.0,
) -> list[dict[str, Any]]:
    counts = list(hourly_counts.values())
    if len(counts) < 2:
        return []

    stdev = statistics.stdev(counts)
    if stdev == 0:
        return []

    mean = statistics.mean(counts)
    threshold = mean + threshold_sigma * stdev
    anomalies = []

    for hour, count in sorted(hourly_counts.items()):
        if count <= threshold:
            continue
        anomalies.append(
            {
                "hour": hour,
                "requests": count,
                "z_score": round((count - mean) / stdev, 2),
                "threshold_sigma": threshold_sigma,
                "threshold_requests": round(threshold, 2),
            },
        )

    return anomalies


def analyze_access_lines(lines: list[str]) -> dict[str, Any]:
    ip_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    hourly_counts: Counter[str] = Counter()
    suspicious: list[dict[str, Any]] = []

    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue

        ip_counts[parsed["ip"]] += 1
        status_counts[parsed["status"]] += 1

        if hour := hour_bucket(parsed["timestamp"]):
            hourly_counts[hour] += 1

        categories = attack_categories(parsed["path"])
        if categories:
            suspicious.append(
                {
                    "ip": parsed["ip"],
                    "timestamp": parsed["timestamp"],
                    "method": parsed["method"],
                    "path": parsed["path"],
                    "status": int(parsed["status"]),
                    "categories": categories,
                },
            )

    return {
        "suspicious_requests": suspicious,
        "top_ips": [
            {"ip": ip, "requests": count}
            for ip, count in ip_counts.most_common(5)
        ],
        "status_distribution": dict(sorted(status_counts.items())),
        "hourly_counts": dict(sorted(hourly_counts.items())),
        "anomalies": detect_anomalies(hourly_counts),
    }


def analyze_access_log(path: str) -> dict[str, Any]:
    return analyze_access_lines(Path(path).read_text(encoding="utf-8").splitlines())


def generate_markdown_report(analysis: dict[str, Any]) -> str:
    lines = [
        "# Web Log Analysis Report",
        "",
        "## Suspicious Requests",
    ]

    if analysis["suspicious_requests"]:
        lines.extend(["| IP | Status | Categories | Path |", "| --- | --- | --- | --- |"])
        for item in analysis["suspicious_requests"]:
            lines.append(
                "| {ip} | {status} | {categories} | `{path}` |".format(
                    ip=item["ip"],
                    status=item["status"],
                    categories=", ".join(item["categories"]),
                    path=item["path"].replace("|", "%7C"),
                ),
            )
    else:
        lines.append("No suspicious requests detected.")

    lines.extend(["", "## Top 5 IPs", "| IP | Requests |", "| --- | ---: |"])
    for item in analysis["top_ips"]:
        lines.append(f"| {item['ip']} | {item['requests']} |")

    lines.extend(["", "## HTTP Status Codes", "| Status | Count |", "| --- | ---: |"])
    for status, count in analysis["status_distribution"].items():
        lines.append(f"| {status} | {count} |")

    lines.extend(["", "## Hourly Anomalies"])
    if analysis["anomalies"]:
        for item in analysis["anomalies"]:
            lines.append(
                "[ANOMALY] {hour} - {requests} requests "
                "(z={z_score}, threshold={threshold_sigma} sigma)".format(**item),
            )
    else:
        lines.append("No hourly anomalies detected.")

    return "\n".join(lines) + "\n"


def write_json(
    data: dict[str, Any],
    output_path: str | None = None,
    stream: TextIO = sys.stdout,
) -> None:
    if output_path:
        Path(output_path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return

    json.dump(data, stream, indent=2)
    stream.write("\n")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze web access logs")
    parser.add_argument("--input", default="access.log", help="Access log path")
    parser.add_argument("--output", help="Optional JSON output path")
    parser.add_argument("--report", help="Optional Markdown report path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    analysis = analyze_access_log(args.input)

    if args.report:
        Path(args.report).write_text(generate_markdown_report(analysis), encoding="utf-8")

    write_json(analysis, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
