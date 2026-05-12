"""Integrated reconnaissance tool for the SPTI automation lab."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from parse_scan import parse_nmap_xml


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
]
HEADER_NAMES = [
    "Server",
    "X-Powered-By",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
]


def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def detect_mode(target: str, requested_mode: str | None = None) -> str:
    if requested_mode:
        return requested_mode
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "domain"
    return "ip"


def safe_target_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_") or "target"


def default_output_dir(target: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"recon_{safe_target_name(target)}_{timestamp}")


def summarize(text: str, limit: int = 1000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"


class AuditLog:
    def __init__(self, path: Path, verbose: bool = False) -> None:
        self.path = path
        self.verbose = verbose

    def record(self, entry: dict[str, Any]) -> None:
        entry = {"timestamp": now_iso(), **entry}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        if self.verbose:
            status = entry.get("status", "unknown")
            action = entry.get("action", "action")
            print(f"[{status}] {action}", file=sys.stderr)


def run_command(
    command: list[str],
    audit: AuditLog,
    action: str,
    timeout: float = 20.0,
) -> dict[str, Any]:
    command_text = shlex.join(command)
    base = {"action": action, "command": command_text}

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        result = {
            **base,
            "status": "error",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"command not found: {command[0]}",
        }
        audit.record(result)
        return result
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        result = {
            **base,
            "status": "error",
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "error": f"timeout after {timeout} seconds",
        }
        audit.record(
            {
                **result,
                "stdout": summarize(stdout),
                "stderr": summarize(stderr),
            },
        )
        return result

    result = {
        **base,
        "status": "success" if completed.returncode == 0 else "error",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": None if completed.returncode == 0 else summarize(completed.stderr),
    }
    audit.record(
        {
            **result,
            "stdout": summarize(completed.stdout),
            "stderr": summarize(completed.stderr),
        },
    )
    return result


def extract_field(text: str, labels: list[str]) -> str | None:
    for label in labels:
        pattern = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
        for line in text.splitlines():
            if match := pattern.match(line):
                value = match.group("value").strip()
                if value:
                    return value
    return None


def parse_domain_whois(text: str) -> dict[str, str | None]:
    return {
        "registrar": extract_field(text, ["Registrar", "Sponsoring Registrar"]),
        "creation_date": extract_field(
            text,
            ["Creation Date", "Created On", "Registration Date", "Registration Time"],
        ),
        "expiry_date": extract_field(
            text,
            [
                "Registry Expiry Date",
                "Registrar Registration Expiration Date",
                "Expiry Date",
                "Expiration Date",
            ],
        ),
        "registrant_organization": extract_field(
            text,
            ["Registrant Organization", "Registrant Org"],
        ),
    }


def parse_ip_whois(text: str) -> dict[str, str | None]:
    return {
        "organization": extract_field(
            text,
            ["OrgName", "org-name", "Organization", "Org", "descr", "netname"],
        ),
        "country": extract_field(text, ["Country"]),
    }


def parse_dig_records(stdout: str) -> list[str]:
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def parse_headers(stdout: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    wanted = {header.lower(): header for header in HEADER_NAMES}

    for line in stdout.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        canonical = wanted.get(name.strip().lower())
        if canonical and canonical not in headers:
            headers[canonical] = value.strip()

    return headers


def missing_security_headers(headers: dict[str, str]) -> list[str]:
    present = {name.lower() for name in headers}
    return [header for header in SECURITY_HEADERS if header.lower() not in present]


def domain_recon(target: str, audit: AuditLog) -> dict[str, Any]:
    whois_result = run_command(["whois", target], audit, "whois domain", timeout=20)
    whois_data = parse_domain_whois(whois_result["stdout"]) if whois_result["stdout"] else {}

    dig_data: dict[str, Any] = {}
    for record_type in ("A", "MX", "NS", "TXT"):
        result = run_command(
            ["dig", "+short", target, record_type],
            audit,
            f"dig {record_type}",
            timeout=10,
        )
        dig_data[record_type] = {
            "success": result["status"] == "success",
            "records": parse_dig_records(result["stdout"]),
            "error": result["error"],
        }

    curl_result = run_command(
        ["curl", "-I", "--max-time", "10", f"https://{target}"],
        audit,
        "curl headers",
        timeout=12,
    )
    headers = parse_headers(curl_result["stdout"])

    return {
        "whois": {
            "success": whois_result["status"] == "success",
            **whois_data,
            "error": whois_result["error"],
        },
        "dig": dig_data,
        "curl": {
            "success": curl_result["status"] == "success",
            "headers": headers,
            "missing_security_headers": missing_security_headers(headers),
            "error": curl_result["error"],
        },
    }


def ip_recon(target: str, audit: AuditLog) -> dict[str, Any]:
    nmap_result = run_command(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", "-", target],
        audit,
        "nmap service scan",
        timeout=60,
    )

    hosts: list[dict[str, Any]] = []
    nmap_error = nmap_result["error"]
    if nmap_result["stdout"]:
        try:
            hosts = parse_nmap_xml(nmap_result["stdout"])
        except Exception as exc:  # XML parser errors should not stop later steps.
            nmap_error = f"failed to parse nmap XML: {exc}"

    reverse_result = run_command(
        ["dig", "-x", target, "+short"],
        audit,
        "reverse dns",
        timeout=10,
    )

    whois_result = run_command(["whois", target], audit, "whois ip", timeout=20)
    whois_data = parse_ip_whois(whois_result["stdout"]) if whois_result["stdout"] else {}

    return {
        "nmap": {
            "success": nmap_result["status"] == "success" and nmap_error is None,
            "hosts": hosts,
            "error": nmap_error,
        },
        "reverse_dns": {
            "success": reverse_result["status"] == "success",
            "records": parse_dig_records(reverse_result["stdout"]),
            "error": reverse_result["error"],
        },
        "whois": {
            "success": whois_result["status"] == "success",
            **whois_data,
            "error": whois_result["error"],
        },
    }


def collect_results(target: str, mode: str, audit: AuditLog) -> dict[str, Any]:
    timestamp = now_iso()
    data: dict[str, Any] = {
        "target": target,
        "mode": mode,
        "timestamp": timestamp,
    }

    if mode == "domain":
        data.update(domain_recon(target, audit))
    else:
        data.update(ip_recon(target, audit))

    return data


def open_port_rows(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in results.get("nmap", {}).get("hosts", []):
        for port in host.get("open_ports", []):
            rows.append(
                {
                    "ip": host.get("ip"),
                    "port": port.get("port"),
                    "service": port.get("service"),
                    "version": port.get("version"),
                },
            )
    return rows


def tool_errors(results: dict[str, Any]) -> list[tuple[str, str]]:
    errors: list[tuple[str, str]] = []
    for key, value in results.items():
        if not isinstance(value, dict):
            continue
        if error := value.get("error"):
            errors.append((key, str(error)))
        for child_key, child_value in value.items():
            if isinstance(child_value, dict) and child_value.get("error"):
                errors.append((f"{key}.{child_key}", str(child_value["error"])))
    return errors


def summary_rows(results: dict[str, Any]) -> list[tuple[str, str, str]]:
    if results["mode"] == "ip":
        ports = open_port_rows(results)
        return [
            ("nmap", "ok" if results.get("nmap", {}).get("success") else "error", f"{len(ports)} open ports"),
            (
                "reverse_dns",
                "ok" if results.get("reverse_dns", {}).get("success") else "error",
                ", ".join(results.get("reverse_dns", {}).get("records", [])) or "no records",
            ),
            (
                "whois",
                "ok" if results.get("whois", {}).get("success") else "error",
                results.get("whois", {}).get("organization") or "organization not found",
            ),
        ]

    dig_records = sum(
        len(value.get("records", []))
        for value in results.get("dig", {}).values()
        if isinstance(value, dict)
    )
    dig_success = all(
        value.get("success")
        for value in results.get("dig", {}).values()
        if isinstance(value, dict)
    )
    return [
        (
            "whois",
            "ok" if results.get("whois", {}).get("success") else "error",
            results.get("whois", {}).get("registrar") or "registrar not found",
        ),
        ("dig", "ok" if dig_success else "error", f"{dig_records} DNS records"),
        (
            "curl",
            "ok" if results.get("curl", {}).get("success") else "error",
            f"{len(results.get('curl', {}).get('headers', {}))} relevant headers",
        ),
    ]


def generate_report(results: dict[str, Any]) -> str:
    lines = [
        f"# Recon Report: {results['target']}",
        "",
        f"- Mode: {results['mode']}",
        f"- Timestamp: {results['timestamp']}",
        "",
        "## Summary",
        "| Tool | Status | Finding |",
        "| --- | --- | --- |",
    ]

    for tool, status, finding in summary_rows(results):
        lines.append(f"| {tool} | {status} | {finding} |")

    if results["mode"] == "ip":
        lines.extend(["", "## Open Ports"])
        rows = open_port_rows(results)
        if rows:
            lines.extend(["| IP | Port | Service | Version |", "| --- | ---: | --- | --- |"])
            for row in rows:
                lines.append(
                    f"| {row['ip']} | {row['port']} | {row['service']} | {row['version'] or ''} |",
                )
        else:
            lines.append("No open ports were reported.")
    else:
        lines.extend(["", "## DNS Records"])
        for record_type, data in results.get("dig", {}).items():
            records = data.get("records", [])
            lines.append(f"### {record_type}")
            lines.extend([f"- `{record}`" for record in records] or ["No records found."])

        lines.extend(["", "## HTTP Headers"])
        headers = results.get("curl", {}).get("headers", {})
        if headers:
            lines.extend(["| Header | Value |", "| --- | --- |"])
            for name, value in headers.items():
                lines.append(f"| {name} | `{value}` |")
        else:
            lines.append("No relevant HTTP headers were captured.")

    lines.extend(["", "## Missing Security Headers"])
    if results["mode"] == "domain":
        missing = results.get("curl", {}).get("missing_security_headers", SECURITY_HEADERS)
        lines.extend([f"- {header}" for header in missing] or ["None."])
    else:
        lines.append("Not applicable in IP mode; HTTP headers are only checked in domain mode.")

    lines.extend(["", "## Tool Errors"])
    errors = tool_errors(results)
    if errors:
        lines.extend([f"- {tool}: {error}" for tool, error in errors])
    else:
        lines.append("No tool errors recorded.")

    lines.extend(
        [
            "",
            "## Ethical Note",
            "Run this tool only against systems you own or are explicitly authorized to test.",
        ],
    )
    return "\n".join(lines) + "\n"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Integrated reconnaissance tool")
    parser.add_argument("target", help="Domain or IP address to inspect")
    parser.add_argument("--mode", choices=["domain", "ip"], help="Recon mode")
    parser.add_argument(
        "--output",
        help="Output directory. Defaults to ./recon_<target>_<timestamp>/",
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    mode = detect_mode(args.target, args.mode)
    output_dir = Path(args.output) if args.output else default_output_dir(args.target)
    output_dir.mkdir(parents=True, exist_ok=True)

    audit = AuditLog(output_dir / "audit.log", verbose=args.verbose)
    audit.record({"action": "start", "status": "success", "target": args.target, "mode": mode})

    results = collect_results(args.target, mode, audit)
    (output_dir / "results.json").write_text(
        json.dumps(results, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(generate_report(results), encoding="utf-8")

    audit.record({"action": "finish", "status": "success", "output_dir": str(output_dir)})
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
