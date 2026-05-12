"""Parse nmap XML output and enrich SSH hosts with ssh-keyscan."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable


SSH_KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-",
    "sk-ssh-ed25519",
    "sk-ecdsa-sha2-",
)


def service_version(service: ET.Element | None) -> str:
    if service is None:
        return ""

    parts = [
        service.get("product", "").strip(),
        service.get("version", "").strip(),
        service.get("extrainfo", "").strip(),
    ]
    return " ".join(part for part in parts if part)


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Return structured host findings from nmap XML text."""
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []

    for host in root.findall("host"):
        address = None
        for query in ("address[@addrtype='ipv4']", "address[@addrtype='ipv6']", "address"):
            address = host.find(query)
            if address is not None:
                break
        if address is None:
            continue

        hostname_elem = host.find("hostnames/hostname")
        open_ports: list[dict[str, Any]] = []

        for port_elem in host.findall("ports/port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            try:
                port_number = int(port_elem.get("portid", ""))
            except ValueError:
                continue

            service = port_elem.find("service")
            open_ports.append(
                {
                    "port": port_number,
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "version": service_version(service),
                },
            )

        if not open_ports:
            continue

        hosts.append(
            {
                "ip": address.get("addr", ""),
                "hostname": hostname_elem.get("name") if hostname_elem is not None else None,
                "open_ports": open_ports,
            },
        )

    return hosts


def extract_ssh_key_type(keyscan_output: str) -> str | None:
    for line in keyscan_output.splitlines():
        if not line.strip() or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        key_type = parts[1]
        if key_type.startswith(SSH_KEY_TYPES):
            return key_type

    return None


def ssh_keyscan(ip: str, timeout: float) -> str | None:
    """Run ssh-keyscan and return the first key type found, or None."""
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(max(1, math.ceil(timeout))), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    return extract_ssh_key_type(result.stdout)


def host_has_ssh(host: dict[str, Any]) -> bool:
    return any(port.get("port") == 22 for port in host.get("open_ports", []))


def enrich_ssh_keys(
    hosts: list[dict[str, Any]],
    timeout: float,
    keyscan: Callable[[str, float], str | None] = ssh_keyscan,
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for host in hosts:
        host_copy = {
            "ip": host["ip"],
            "hostname": host.get("hostname"),
            "open_ports": host.get("open_ports", []),
        }
        if host_has_ssh(host_copy):
            host_copy["ssh_host_key_type"] = keyscan(host_copy["ip"], timeout)
        enriched.append(host_copy)

    return enriched


def load_and_enrich(input_path: str, ssh_timeout: float) -> list[dict[str, Any]]:
    xml_text = Path(input_path).read_text(encoding="utf-8")
    hosts = parse_nmap_xml(xml_text)
    return enrich_ssh_keys(hosts, ssh_timeout)


def write_json(data: Any, output_path: str) -> None:
    Path(output_path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse and enrich nmap XML output")
    parser.add_argument("--input", default="scan.xml", help="nmap XML input file")
    parser.add_argument("--output", default="hosts.json", help="JSON output file")
    parser.add_argument(
        "--ssh-timeout",
        type=float,
        default=5.0,
        help="Timeout for ssh-keyscan in seconds",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.ssh_timeout <= 0:
        parser.error("--ssh-timeout must be greater than 0")

    hosts = load_and_enrich(args.input, args.ssh_timeout)
    write_json(hosts, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
