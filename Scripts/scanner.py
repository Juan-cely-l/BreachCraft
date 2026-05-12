"""Concurrent TCP connect scanner for the SPTI automation lab."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO


MIN_PORT = 1
MAX_PORT = 65535


def parse_ports(port_spec: str) -> list[int]:
    """Parse comma-separated ports and ranges into a sorted unique list."""
    ports: set[int] = set()

    for raw_part in port_spec.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("empty port entry")

        if "-" in part:
            bounds = [value.strip() for value in part.split("-")]
            if len(bounds) != 2 or not all(bounds):
                raise ValueError(f"invalid port range: {part}")
            start, end = (int(value) for value in bounds)
            if start > end:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    invalid = [port for port in ports if port < MIN_PORT or port > MAX_PORT]
    if invalid:
        raise ValueError("ports must be between 1 and 65535")

    return sorted(ports)


async def scan_port(host: str, port: int, timeout: float) -> int | None:
    """Return the port number when a TCP connection succeeds."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host(
    host: str,
    ports: list[int],
    rate: int,
    timeout: float,
) -> list[int]:
    """Scan a host while limiting concurrent connections with a semaphore."""
    semaphore = asyncio.Semaphore(rate)

    async def limited_scan(port: int) -> int | None:
        async with semaphore:
            return await scan_port(host, port, timeout)

    results = await asyncio.gather(*(limited_scan(port) for port in ports))
    return sorted(port for port in results if port is not None)


def build_result(target: str, open_ports: list[int], elapsed: float) -> dict[str, Any]:
    return {
        "target": target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.now().replace(microsecond=0).isoformat(),
        "open_ports": open_ports,
    }


def write_result(
    result: dict[str, Any],
    output_path: str | None = None,
    stream: TextIO = sys.stdout,
) -> None:
    if output_path:
        Path(output_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return

    json.dump(result, stream, indent=2)
    stream.write("\n")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Concurrent TCP port scanner",
        epilog=(
            "Examples:\n"
            "  python scanner.py 192.168.1.1\n"
            "  python scanner.py 127.0.0.1 --ports 1-1024 --rate 200\n"
            "  python scanner.py 10.0.0.5 --ports 22,80,100-110 --output results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="IP address or host to scan")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan, e.g. 1-1024, 22,80,443, or 22,80,100-110",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=200,
        help="Maximum concurrent connections",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Per-port timeout in seconds",
    )
    parser.add_argument("--output", help="JSON output file")
    return parser


async def run_scan(args: argparse.Namespace) -> dict[str, Any]:
    ports = parse_ports(args.ports)
    start = time.perf_counter()
    open_ports = await scan_host(args.target, ports, args.rate, args.timeout)
    elapsed = time.perf_counter() - start
    return build_result(args.target, open_ports, elapsed)


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.rate < 1:
        parser.error("--rate must be greater than 0")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        result = asyncio.run(run_scan(args))
    except ValueError as exc:
        parser.error(str(exc))

    write_result(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
