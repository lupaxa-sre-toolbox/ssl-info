"""Command-line interface."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from test_lookup import _leaf

from lupaxa.ssl_info.cli import (
    expand_domains,
    format_block,
    format_blocks,
    format_instant,
    main,
    read_domains,
)
from lupaxa.ssl_info.lookup import InfoResult, lookup


def _ok(
    host: str,
    *,
    issuer: str | None = "CN=R3, O=Let's Encrypt",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> InfoResult:
    return InfoResult(
        host,
        "ok",
        subject="CN=www.example.com",
        issuer=issuer,
        version="v3",
        serial="4A3F2",
        not_before=not_before,
        not_after=not_after,
        signature="sha256WithRSAEncryption",
        public_key="RSA 2048",
    )


def test_format_instant_ordinals() -> None:
    assert format_instant(datetime(2026, 11, 11, tzinfo=UTC)) == "11th November 2026 00:00:00 UTC"
    assert (
        format_instant(datetime(2026, 1, 1, 1, 2, 3, tzinfo=UTC)) == "1st January 2026 01:02:03 UTC"
    )
    assert format_instant(datetime(2026, 1, 2, tzinfo=UTC)) == "2nd January 2026 00:00:00 UTC"
    assert format_instant(datetime(2026, 1, 3, tzinfo=UTC)) == "3rd January 2026 00:00:00 UTC"
    assert format_instant(datetime(2026, 11, 9, 23, 59, 59, tzinfo=UTC)) == (
        "9th November 2026 23:59:59 UTC"
    )
    assert format_instant(datetime(2026, 11, 12, tzinfo=UTC)) == "12th November 2026 00:00:00 UTC"
    assert format_instant(datetime(2026, 11, 13, tzinfo=UTC)) == "13th November 2026 00:00:00 UTC"


def test_format_block_labels_and_missing_field() -> None:
    when = datetime(2026, 11, 9, 23, 59, 59, tzinfo=UTC)
    block = format_block(_ok("example.com", not_before=when, not_after=when))
    lines = block.splitlines()
    assert lines[0] == "example.com"
    assert "  Subject: CN=www.example.com" in lines
    assert "  Not After: 9th November 2026 23:59:59 UTC" in lines
    assert "  Subject Alternative Names: —" in lines
    assert "  Error:" not in block


def test_ok_host_prints_leaf_fields_in_order(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    not_before = datetime(2026, 8, 11, tzinfo=UTC)
    not_after = datetime(2026, 11, 9, 23, 59, 59, tzinfo=UTC)
    leaf = _leaf(
        not_before=not_before,
        not_after=not_after,
        subject_alternative_names=(("DNS", "example.com"), ("DNS", "www.example.com")),
        key_usage=("digital_signature", "key_encipherment"),
        extended_key_usage=("serverAuth",),
        basic_constraints=(False, None),
        authority_key_identifier=bytes.fromhex("142eb317"),
        subject_key_identifier=bytes.fromhex("a1b2c3d4"),
        certificate_policies=("2.23.140.1.2.1",),
        crl_distribution_points=("http://crl.example/example.crl",),
        authority_information_access=(
            ("OCSP", "http://ocsp.example"),
            ("CA Issuers", "http://certs.example/ca.crt"),
        ),
    )

    def fake(host: str, timeout: float) -> InfoResult:
        return lookup(host, timeout=timeout, probe=lambda _host, _timeout: leaf)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["example.com"]) == 0
    access = "OCSP: http://ocsp.example, CA Issuers: http://certs.example/ca.crt"
    assert capsys.readouterr().out.splitlines() == [
        "example.com",
        "  Subject: CN=www.example.com",
        "  Issuer: CN=R3, O=Let's Encrypt",
        "  Version: v3",
        "  Serial: 4A3F2",
        f"  Not Before: {format_instant(not_before)}",
        f"  Not After: {format_instant(not_after)}",
        "  Signature: sha256WithRSAEncryption",
        "  Public Key: RSA 2048",
        "  Subject Alternative Names: DNS:example.com, DNS:www.example.com",
        "  Key Usage: digital_signature, key_encipherment",
        "  Extended Key Usage: serverAuth",
        "  Basic Constraints: CA: false",
        "  Authority Key Identifier: 14:2E:B3:17",
        "  Subject Key Identifier: A1:B2:C3:D4",
        "  Certificate Policies: 2.23.140.1.2.1",
        "  CRL Distribution Points: http://crl.example/example.crl",
        f"  Authority Information Access: {access}",
    ]


def test_found_fields_and_chain_are_printed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    extra = replace(
        _leaf(subject=(("commonName", "Intermediate"),)),
        extensions=(("Basic Constraints", "CA: true"),),
        fingerprint_sha256="AA:BB",
    )
    leaf = replace(
        _leaf(),
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256 (128 bits)",
        alpn="h2",
        fingerprint_sha256="CC:DD",
        extensions=(("Key Usage", "digital_signature"),),
        chain=(extra,),
    )

    def fake(host: str, timeout: float) -> InfoResult:
        return lookup(host, timeout=timeout, probe=lambda _host, _timeout: leaf)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["example.com"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "  TLS Version: TLSv1.3" in lines
    assert "  Cipher: TLS_AES_128_GCM_SHA256 (128 bits)" in lines
    assert "  ALPN: h2" in lines
    assert "  Fingerprint SHA-256: CC:DD" in lines
    assert "  Key Usage: digital_signature" in lines
    assert "example.com chain 2" in lines
    assert "  Basic Constraints: CA: true" in lines
    assert not any(line.startswith("  Subject Alternative Names:") for line in lines)


def test_error_blocks_omit_field_labels() -> None:
    blocks = format_blocks(
        [
            InfoResult("slow.test", "error", error="timed out"),
            InfoResult("nope.invalid", "invalid"),
        ]
    )
    assert blocks == "slow.test\n  Error: timed out\n\nnope.invalid\n  Error: Invalid Host"


def test_read_domains_skips_comments(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("# note\n\nexample.com  # prod\n", encoding="utf-8")
    assert read_domains(str(path)) == ["example.com"]


def test_expand_domains_splits_commas() -> None:
    assert expand_domains(["example.com,example.org", " example.net "]) == [
        "example.com",
        "example.org",
        "example.net",
    ]


def test_help_version_and_missing_host(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    assert "HOST" in capsys.readouterr().out
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()
    assert main([]) == 2
    assert "usage:" in capsys.readouterr().out.lower()


def test_http_scheme_is_removed_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[str] = []

    def fake(host: str, **_kwargs: object) -> InfoResult:
        seen.append(host)
        return _ok(host)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["https://example.com", "HTTP://other.example", "ftp://nope.example"]) == 0
    assert seen == ["example.com", "other.example", "ftp://nope.example"]
    err = capsys.readouterr().err
    assert "removed https:// from https://example.com; it is not needed" in err
    assert "removed http:// from HTTP://other.example; it is not needed" in err
    assert "ftp://" not in err


def test_scheme_with_a_path_stays_invalid(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["https://example.com/docs"]) == 1
    captured = capsys.readouterr()
    assert "removed https:// from https://example.com/docs; it is not needed" in captured.err
    assert captured.out == "example.com/docs\n  Error: Invalid Host\n"


def test_file_and_comma_order(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    seen: list[str] = []

    def fake(host: str, **_kwargs: object) -> InfoResult:
        seen.append(host)
        return _ok(host)

    path = tmp_path / "hosts.txt"
    path.write_text("file.example,other.example\n", encoding="utf-8")
    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["cli.example", "--file", str(path)]) == 0
    assert seen == ["cli.example", "file.example", "other.example"]
    assert "Subject:" in capsys.readouterr().out


def test_stdin_file(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake(host: str, **_kwargs: object) -> InfoResult:
        seen.append(host)
        return _ok(host)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    monkeypatch.setattr("lupaxa.ssl_info.cli.sys.stdin", StringIO("example.com\n# skip\n"))
    assert main(["--file", "-"]) == 0
    assert seen == ["example.com"]


def test_sort_missing_values_stay_last(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2027, 1, 1, tzinfo=UTC)
    rows = {
        "b.example": _ok("b.example", issuer="CN=B", not_after=early),
        "a.example": _ok("a.example", issuer="CN=a", not_after=late),
        "z.example": _ok("z.example", issuer=None, not_after=None),
    }

    def fake(host: str, **_kwargs: object) -> InfoResult:
        return rows[host]

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["z.example", "b.example", "a.example", "--sort", "host"]) == 0
    output = capsys.readouterr().out
    assert output.index("a.example") < output.index("b.example") < output.index("z.example")
    assert main(["z.example", "b.example", "a.example", "--sort", "issuer", "--order", "desc"]) == 0
    issuer_out = capsys.readouterr().out
    assert issuer_out.index("b.example") < issuer_out.index("a.example")
    assert issuer_out.index("a.example") < issuer_out.index("z.example")
    assert main(["z.example", "b.example", "a.example", "--sort", "not-after"]) == 0
    date_out = capsys.readouterr().out
    assert date_out.index("b.example") < date_out.index("a.example") < date_out.index("z.example")


def test_sort_not_before_missing_stays_last(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2027, 1, 1, tzinfo=UTC)
    rows = {
        "b.example": _ok("b.example", not_before=early),
        "a.example": _ok("a.example", not_before=late),
        "z.example": _ok("z.example", not_before=None),
    }

    def fake(host: str, **_kwargs: object) -> InfoResult:
        return rows[host]

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["z.example", "b.example", "a.example", "--sort", "not-before"]) == 0
    output = capsys.readouterr().out
    assert output.index("b.example") < output.index("a.example") < output.index("z.example")


def test_order_requires_sort(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["example.com", "--order", "ascending"]) == 2
    assert "--order requires --sort" in capsys.readouterr().err


def test_bad_timeout() -> None:
    assert main(["example.com", "--timeout", "0"]) == 2
    assert main(["example.com", "--timeout", "nope"]) == 2


def test_module_argv_names_ssl_info(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["lupaxa/ssl_info/__main__.py"])
    assert main(["--timeout", "0", "example.com"]) == 2
    error = capsys.readouterr().err
    assert "ssl-info" in error
    assert "__main__.py" not in error


def test_timeout_reaches_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []

    def fake(host: str, timeout: float) -> InfoResult:
        seen.append(timeout)
        return _ok(host)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["--timeout", "5", "example.com"]) == 0
    assert seen == [5.0]


def test_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(host: str, **_kwargs: object) -> InfoResult:
        if host == "bad.example":
            return InfoResult("bad.example", "invalid")
        if host == "slow.example":
            return InfoResult("slow.example", "error", error="timed out")
        return _ok(host)

    monkeypatch.setattr("lupaxa.ssl_info.cli.lookup", fake)
    assert main(["example.com"]) == 0
    assert main(["bad.example"]) == 1
    assert main(["slow.example"]) == 2
    assert main(["bad.example", "slow.example"]) == 1


def test_unreadable_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--file", "no-such-hosts.txt"]) == 2
    assert "no-such-hosts.txt" in capsys.readouterr().err
