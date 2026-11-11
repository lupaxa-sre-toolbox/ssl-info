"""Command-line interface for TLS leaf-certificate details."""

from __future__ import annotations

import argparse
import math
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from .lookup import DEFAULT_TIMEOUT, InfoResult, lookup
from .version import get_version


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than 0")
    return timeout


def _sort_order(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"asc", "ascending"}:
        return "ascending"
    if normalized in {"desc", "descending"}:
        return "descending"
    raise argparse.ArgumentTypeError("order must be ascending or descending")


def _read_error_detail(exc: OSError | UnicodeDecodeError) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    text = str(exc).strip() or exc.__class__.__name__
    return " ".join(text.split())


def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None:
        return 0
    return code if isinstance(code, int) else 1


def _program_name(argv0: str) -> str:
    name = os.path.basename(argv0)
    return "ssl-info" if name == "__main__.py" else name


def build_parser() -> argparse.ArgumentParser:
    """Build the ``ssl-info`` argument parser."""
    parser = argparse.ArgumentParser(
        prog=_program_name(sys.argv[0]),
        description="Show TLS leaf-certificate details for port 443.",
    )
    parser.add_argument(
        "hosts",
        nargs="*",
        metavar="HOST",
        help="Hostname to inspect; repeat for more than one",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="File of hostnames, one per line (`-` reads stdin)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "-s",
        "--sort",
        choices=("host", "issuer", "not-before", "not-after"),
        help="Sort blocks by host, issuer, not-before, or not-after",
    )
    parser.add_argument(
        "--order",
        type=_sort_order,
        default=None,
        metavar="DIRECTION",
        help="Sort ascending or descending (default: ascending)",
    )
    parser.add_argument("--version", action="version", version=get_version())
    return parser


def expand_domains(values: list[str]) -> list[str]:
    """Split host tokens on commas and drop empty pieces."""
    hosts: list[str] = []
    for value in values:
        hosts.extend(part.strip() for part in value.split(",") if part.strip())
    return hosts


def _strip_http_scheme(host: str) -> tuple[str, str | None]:
    """Return the host and a removed ``http://`` or ``https://`` scheme."""
    lowered = host.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            return host[len(scheme) :], scheme
    return host, None


def read_domains(path: str) -> list[str]:
    """Return hostnames from a text file, skipping blanks and ``#`` comments."""
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    hosts: list[str] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            hosts.append(stripped)
    return hosts


_MISSING = "—"
_MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
_CORE_FIELDS = (
    ("Subject", "subject"),
    ("Issuer", "issuer"),
    ("Version", "version"),
    ("Serial", "serial"),
    ("Not Before", "not_before"),
    ("Not After", "not_after"),
    ("Signature", "signature"),
    ("Public Key", "public_key"),
)
_FOUND_FIELDS = (
    ("TLS Version", "tls_version"),
    ("Cipher", "cipher"),
    ("ALPN", "alpn"),
    ("Fingerprint SHA-1", "fingerprint_sha1"),
    ("Fingerprint SHA-256", "fingerprint_sha256"),
)
_EXTENSION_FIELDS = (
    ("Subject Alternative Names", "subject_alternative_names"),
    ("Key Usage", "key_usage"),
    ("Extended Key Usage", "extended_key_usage"),
    ("Basic Constraints", "basic_constraints"),
    ("Authority Key Identifier", "authority_key_identifier"),
    ("Subject Key Identifier", "subject_key_identifier"),
    ("Certificate Policies", "certificate_policies"),
    ("CRL Distribution Points", "crl_distribution_points"),
    ("Authority Information Access", "authority_information_access"),
)


def format_instant(when: datetime) -> str:
    """Return an ordinal UTC date and time, such as ``11th November 2026 00:00:00 UTC``."""
    moment = when.astimezone(UTC)
    suffix = (
        "th"
        if 11 <= moment.day % 100 <= 13
        else {1: "st", 2: "nd", 3: "rd"}.get(moment.day % 10, "th")
    )
    clock = f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
    return f"{moment.day}{suffix} {_MONTHS[moment.month - 1]} {moment.year} {clock} UTC"


def _field_line(label: str, attr: str, result: InfoResult, *, missing: bool) -> str | None:
    raw = getattr(result, attr)
    if attr in {"not_before", "not_after"}:
        if isinstance(raw, datetime):
            return f"  {label}: {format_instant(raw)}"
        return f"  {label}: {_MISSING}" if missing else None
    if raw:
        return f"  {label}: {raw}"
    return f"  {label}: {_MISSING}" if missing else None


def format_block(result: InfoResult) -> str:
    """Return one host heading and its detail lines."""
    lines = [result.host]
    if result.status == "invalid":
        lines.append("  Error: Invalid Host")
        return "\n".join(lines)
    if result.status != "ok":
        lines.append(f"  Error: {result.error or 'lookup failed'}")
        return "\n".join(lines)
    for label, attr in _CORE_FIELDS:
        line = _field_line(label, attr, result, missing=True)
        if line is not None:
            lines.append(line)
    for label, attr in _FOUND_FIELDS:
        line = _field_line(label, attr, result, missing=False)
        if line is not None:
            lines.append(line)
    if result.extensions:
        lines.extend(f"  {label}: {value}" for label, value in result.extensions)
    else:
        for label, attr in _EXTENSION_FIELDS:
            line = _field_line(label, attr, result, missing=True)
            if line is not None:
                lines.append(line)
    if not result.chain:
        return "\n".join(lines)
    blocks = ["\n".join(lines)]
    blocks.extend(format_block(item) for item in result.chain)
    return "\n\n".join(blocks)


def format_blocks(results: list[InfoResult]) -> str:
    """Return detail blocks separated by one blank line."""
    return "\n\n".join(format_block(result) for result in results)


def _sort_results(results: list[InfoResult], column: str, *, descending: bool) -> None:
    """Sort ``results`` in place. Blocks with no issuer or date stay last."""
    if column == "host":
        results.sort(key=lambda item: item.host.casefold(), reverse=descending)
        return
    if column == "issuer":
        present = [item for item in results if item.issuer]
        missing = [item for item in results if not item.issuer]
        present.sort(key=lambda item: (item.issuer or "").casefold(), reverse=descending)
        results[:] = present + missing
        return

    def value(item: InfoResult) -> tuple[int, float]:
        stamp_source = item.not_before if column == "not-before" else item.not_after
        if stamp_source is None:
            return (1, 0.0)
        stamp = stamp_source.timestamp()
        return (0, -stamp if descending else stamp)

    results.sort(key=value)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return _exit_code(exc)

    name = _program_name(sys.argv[0])
    hosts = expand_domains(args.hosts)
    for path in args.file:
        try:
            hosts.extend(expand_domains(read_domains(path)))
        except (OSError, UnicodeDecodeError) as exc:
            detail = _read_error_detail(exc)
            print(f"{name}: {detail}: {path}", file=sys.stderr)
            return 2
    if not hosts:
        parser.print_help()
        return 2
    if args.order is not None and args.sort is None:
        print(f"{name}: --order requires --sort", file=sys.stderr)
        return 2

    attention = False
    failed = False
    results: list[InfoResult] = []
    for host in hosts:
        bare, scheme = _strip_http_scheme(host)
        if scheme is not None:
            print(
                f"{name}: removed {scheme} from {host}; it is not needed",
                file=sys.stderr,
            )
        result = lookup(bare, timeout=args.timeout)
        results.append(result)
        if result.status == "invalid":
            attention = True
        elif result.status == "error":
            failed = True
    if args.sort:
        _sort_results(results, args.sort, descending=args.order == "descending")
    print(format_blocks(results))
    if attention:
        return 1
    if failed:
        return 2
    return 0
