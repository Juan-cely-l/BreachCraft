"""Analyze Linux sshd authentication logs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, TextIO


FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port",
)
ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port",
)


def analyze_lines(lines: list[str], threshold: int = 10) -> dict[str, Any]:
    failed_by_ip: Counter[str] = Counter()
    targeted_users: Counter[str] = Counter()
    total_failed = 0
    total_successful = 0

    for line in lines:
        if failed := FAILED_RE.search(line):
            total_failed += 1
            failed_by_ip[failed.group("ip")] += 1
            targeted_users[failed.group("user")] += 1
            continue

        if ACCEPTED_RE.search(line):
            total_successful += 1

    failed_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in failed_by_ip.most_common()
        if count > threshold
    ]
    users = [
        {"user": user, "attempts": count}
        for user, count in targeted_users.most_common()
    ]

    ratio = None
    if total_successful:
        ratio = round(total_failed / total_successful, 2)

    return {
        "failed_ips": failed_ips,
        "targeted_users": users,
        "total_failed": total_failed,
        "total_successful": total_successful,
        "failed_to_successful_ratio": ratio,
    }


def analyze_auth_log(path: str, threshold: int = 10) -> dict[str, Any]:
    return analyze_lines(Path(path).read_text(encoding="utf-8").splitlines(), threshold)


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
    parser = argparse.ArgumentParser(description="Analyze Linux sshd authentication logs")
    parser.add_argument("--input", default="auth.log", help="Authentication log path")
    parser.add_argument("--output", help="Optional JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    result = analyze_auth_log(args.input)
    write_json(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
