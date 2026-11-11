"""TLS leaf-certificate lookup."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from lupaxa.ssl_info.lookup import (
    LeafCert,
    _enabled_key_usages,
    _leaf_from_certificate,
    _oid_label,
    lookup,
    probe_certificate,
)


def _leaf(
    *,
    subject: tuple[tuple[str, str], ...] = (("commonName", "www.example.com"),),
    issuer: tuple[tuple[str, str], ...] = (
        ("commonName", "R3"),
        ("organizationName", "Let's Encrypt"),
    ),
    serial_number: int = 0x4A3F2,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    subject_alternative_names: tuple[tuple[str, str], ...] | None = None,
    key_usage: tuple[str, ...] | None = None,
    extended_key_usage: tuple[str, ...] | None = None,
    basic_constraints: tuple[bool, int | None] | None = None,
    authority_key_identifier: bytes | None = None,
    subject_key_identifier: bytes | None = None,
    certificate_policies: tuple[str, ...] | None = None,
    crl_distribution_points: tuple[str, ...] | None = None,
    authority_information_access: tuple[tuple[str, str], ...] | None = None,
) -> LeafCert:
    if not_before is None:
        not_before = datetime(2026, 8, 11, tzinfo=UTC)
    if not_after is None:
        not_after = datetime(2026, 11, 9, 23, 59, 59, tzinfo=UTC)
    return LeafCert(
        subject=subject,
        issuer=issuer,
        version="v3",
        serial_number=serial_number,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm="sha256WithRSAEncryption",
        public_key="RSA 2048",
        subject_alternative_names=subject_alternative_names,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        basic_constraints=basic_constraints,
        authority_key_identifier=authority_key_identifier,
        subject_key_identifier=subject_key_identifier,
        certificate_policies=certificate_policies,
        crl_distribution_points=crl_distribution_points,
        authority_information_access=authority_information_access,
    )


def test_populated_leaf_formats_fields() -> None:
    result = lookup(
        "Example.COM.",
        probe=lambda _host, _timeout: _leaf(
            subject=(
                ("countryName", "US"),
                ("organizationalUnitName", "Ops"),
                ("organizationName", "Example Inc"),
                ("commonName", "www.example.com"),
                ("organizationalUnitName", "Net"),
            ),
            subject_alternative_names=(
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
            ),
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
        ),
    )
    assert result.host == "example.com"
    assert result.status == "ok"
    assert result.subject == "CN=www.example.com, O=Example Inc, OU=Ops, OU=Net, C=US"
    assert result.issuer == "CN=R3, O=Let's Encrypt"
    assert result.version == "v3"
    assert result.serial == "4A3F2"
    assert result.signature == "sha256WithRSAEncryption"
    assert result.public_key == "RSA 2048"
    assert result.subject_alternative_names == "DNS:example.com, DNS:www.example.com"
    assert result.key_usage == "digital_signature, key_encipherment"
    assert result.extended_key_usage == "serverAuth"
    assert result.basic_constraints == "CA: false"
    assert result.authority_key_identifier == "14:2E:B3:17"
    assert result.subject_key_identifier == "A1:B2:C3:D4"
    assert result.certificate_policies == "2.23.140.1.2.1"
    assert result.crl_distribution_points == "http://crl.example/example.crl"
    assert result.authority_information_access == (
        "OCSP: http://ocsp.example, CA Issuers: http://certs.example/ca.crt"
    )
    assert result.error is None


def test_dn_escaping_and_empty_name() -> None:
    escaped = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(
            subject=(
                ("organizationName", "Example, Inc"),
                ("commonName", "#hash"),
                ("localityName", "City "),
            ),
        ),
    )
    assert escaped.subject == r"CN=\#hash, O=Example\, Inc, L=City\ "
    blank = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(subject=(("commonName", "   "),)),
    )
    assert blank.status == "ok"
    assert blank.subject is None


def test_serial_zero_and_naive_datetime() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(
            serial_number=0,
            not_after=datetime(2026, 11, 9, 23, 59, 59),
        ),
    )
    assert result.serial == "0"
    assert result.not_after == datetime(2026, 11, 9, 23, 59, 59, tzinfo=UTC)


def test_missing_and_empty_extensions_stay_none() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(key_usage=(), certificate_policies=()),
    )
    assert result.key_usage is None
    assert result.certificate_policies is None
    assert result.basic_constraints is None


def test_path_length_zero_is_shown() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(basic_constraints=(True, 0)),
    )
    assert result.basic_constraints == "CA: true, Path Length: 0"


def test_key_usage_order_skips_encipher_without_agreement() -> None:
    quiet = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    assert _enabled_key_usages(quiet) == ("digital_signature", "key_encipherment")
    agreed = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=True,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=True,
        decipher_only=False,
    )
    assert _enabled_key_usages(agreed) == ("key_agreement", "encipher_only")


def _self_signed(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
    *,
    algorithm: hashes.SHA256 | None,
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    subject: x509.Name | None = None,
) -> x509.Certificate:
    if subject is None:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x4A3F2)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 3, 15, tzinfo=UTC))
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(key, algorithm=algorithm)


def test_leaf_from_certificate_reads_extensions() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authority_key_id = bytes.fromhex("142eb317")
    subject_key_id = bytes.fromhex("a1b2c3d4")
    directory = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir.example")])
    crl_uri = "http://crl.example/example.crl"
    ocsp_uri = "http://ocsp.example"
    ca_issuers_uri = "http://certs.example/ca.crt"
    cert = _self_signed(
        key,
        algorithm=hashes.SHA256(),
        extensions=(
            (
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("www.example.com"),
                        x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
                        x509.RFC822Name("admin@example.com"),
                        x509.DirectoryName(directory),
                    ]
                ),
                False,
            ),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                False,
            ),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
            (x509.BasicConstraints(ca=True, path_length=0), False),
            (x509.AuthorityKeyIdentifier(authority_key_id, None, None), False),
            (x509.SubjectKeyIdentifier(subject_key_id), False),
            (
                x509.CertificatePolicies(
                    [x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]
                ),
                False,
            ),
            (
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            [x509.UniformResourceIdentifier(crl_uri)],
                            None,
                            None,
                            None,
                        )
                    ]
                ),
                False,
            ),
            (
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(ocsp_uri),
                        ),
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(ca_issuers_uri),
                        ),
                    ]
                ),
                False,
            ),
        ),
    )
    leaf = _leaf_from_certificate(cert)
    assert leaf.subject_alternative_names == (
        ("DNS", "www.example.com"),
        ("IP", "192.0.2.10"),
        ("email", "admin@example.com"),
        ("DN", "CN=dir.example"),
    )
    assert leaf.signature_algorithm == "sha256WithRSAEncryption"
    assert leaf.key_usage == ("digital_signature", "key_encipherment")
    assert leaf.extended_key_usage == ("serverAuth",)
    assert leaf.basic_constraints == (True, 0)
    assert leaf.authority_key_identifier == authority_key_id
    assert leaf.subject_key_identifier == subject_key_id
    assert leaf.certificate_policies == ("2.23.140.1.2.1",)
    assert leaf.crl_distribution_points == (crl_uri,)
    assert leaf.authority_information_access == (
        ("OCSP", ocsp_uri),
        ("CA Issuers", ca_issuers_uri),
    )
    assert leaf.public_key == "RSA 2048"
    p256 = ec.generate_private_key(ec.SECP256R1())
    p256_leaf = _leaf_from_certificate(_self_signed(p256, algorithm=hashes.SHA256()))
    assert p256_leaf.public_key == "ECDSA P-256"
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_leaf = _leaf_from_certificate(_self_signed(ed_key, algorithm=None))
    assert ed_leaf.public_key == "Ed25519"
    found = dict(leaf.extensions)
    assert found["Subject Alternative Names"] == (
        "DNS:www.example.com, IP:192.0.2.10, email:admin@example.com, DN:CN=dir.example"
    )
    assert found["Key Usage"] == "digital_signature, key_encipherment"
    assert found["Basic Constraints"] == "CA: true, Path Length: 0"
    assert found["Certificate Policies"] == "2.23.140.1.2.1"
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()
    assert leaf.fingerprint_sha256 == ":".join(f"{byte:02X}" for byte in digest)


def test_extra_extensions_are_kept() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unknown = x509.ObjectIdentifier("1.2.3.4.9")
    cert = _self_signed(
        key,
        algorithm=hashes.SHA256(),
        extensions=(
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
            (x509.TLSFeature([x509.TLSFeatureType.status_request]), False),
            (x509.UnrecognizedExtension(unknown, b"\x01\x02"), False),
            (
                x509.CertificatePolicies(
                    [
                        x509.PolicyInformation(
                            x509.ObjectIdentifier("1.2.3.4.5"),
                            ["http://cps.example/policy"],
                        )
                    ]
                ),
                False,
            ),
            (
                x509.NameConstraints(
                    [x509.DNSName("example.com")],
                    [x509.DNSName("no.test")],
                ),
                False,
            ),
            (x509.OCSPNoCheck(), False),
            (x509.InhibitAnyPolicy(0), False),
        ),
    )
    found = dict(_leaf_from_certificate(cert).extensions)
    assert found["Key Usage"] == "critical; digital_signature"
    assert found["TLS Feature"] == "status_request"
    assert found["1.2.3.4.9"] == "01:02"
    assert found["Certificate Policies"] == "1.2.3.4.5 (CPS: http://cps.example/policy)"
    assert found["Name Constraints"] == "permitted DNS:example.com; excluded DNS:no.test"
    assert found["OCSP No Check"] == "yes"
    assert found["Inhibit Any Policy"] == "skip 0"


def test_unregistered_oids_use_dotted_string() -> None:
    unknown = x509.ObjectIdentifier("1.2.3.4.5")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
            x509.NameAttribute(unknown, "custom"),
        ]
    )
    ocsp_uri = "http://ocsp.example"
    ca_issuers_uri = "http://certs.example/ca.crt"
    custom_uri = "http://aia.example/custom"
    cert = _self_signed(
        key,
        algorithm=hashes.SHA256(),
        subject=subject,
        extensions=(
            (x509.ExtendedKeyUsage([unknown]), False),
            (
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(ocsp_uri),
                        ),
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(ca_issuers_uri),
                        ),
                        x509.AccessDescription(
                            unknown,
                            x509.UniformResourceIdentifier(custom_uri),
                        ),
                    ]
                ),
                False,
            ),
        ),
    )
    leaf = _leaf_from_certificate(cert)
    assert ("1.2.3.4.5", "custom") in leaf.subject
    assert ("commonName", "www.example.com") in leaf.subject
    assert "Unknown OID" not in {name for name, _value in leaf.subject}
    assert leaf.extended_key_usage == ("1.2.3.4.5",)
    assert leaf.authority_information_access == (
        ("OCSP", ocsp_uri),
        ("CA Issuers", ca_issuers_uri),
        ("1.2.3.4.5", custom_uri),
    )
    assert leaf.signature_algorithm == "sha256WithRSAEncryption"
    assert _oid_label(NameOID.COMMON_NAME) == "commonName"


def test_invalid_host_does_not_call_the_probe() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise AssertionError("invalid hosts are not probed")

    for host in (
        "https://example.com",
        "example.com:443",
        "  ",
        "not a host",
        "[192.0.2.1]",
        "fe80::1%eth0",
        "[fe80::1%eth0]",
    ):
        result = lookup(host, probe=probe)
        assert result.status == "invalid"
    blank = lookup("   ", probe=probe)
    assert blank.host == "   "
    spaced = lookup("  example.com:443  ", probe=probe)
    assert spaced.host == "example.com:443"


def test_ip_and_idna_hosts_are_normalized() -> None:
    seen: list[str] = []

    def probe(host: str, _timeout: float) -> LeafCert:
        seen.append(host)
        return _leaf()

    assert lookup("192.0.2.10", probe=probe).host == "192.0.2.10"
    assert lookup("[2001:0db8:0000::1]", probe=probe).host == "2001:db8::1"
    assert lookup("2001:db8::1", probe=probe).host == "2001:db8::1"
    assert lookup("münchen.de", probe=probe).host == "xn--mnchen-3ya.de"
    assert lookup("localhost", probe=probe).host == "localhost"
    assert seen == [
        "192.0.2.10",
        "2001:db8::1",
        "2001:db8::1",
        "xn--mnchen-3ya.de",
        "localhost",
    ]


def test_probe_error_collapses_whitespace() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise TimeoutError("timed   out")

    result = lookup("slow.test", probe=probe)
    assert result.status == "error"
    assert result.host == "slow.test"
    assert result.error == "timed out"
    assert result.issuer is None


def test_timeout_must_be_positive() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise AssertionError("bad timeouts are not probed")

    with pytest.raises(ValueError, match="timeout"):
        lookup("example.com", timeout=0, probe=probe)
    with pytest.raises(ValueError, match="timeout"):
        lookup("example.com", timeout=True, probe=probe)


def test_keyboard_interrupt_and_system_exit_propagate() -> None:
    def interrupt(_host: str, _timeout: float) -> LeafCert:
        raise KeyboardInterrupt

    def exit_now(_host: str, _timeout: float) -> LeafCert:
        raise SystemExit(1)

    with pytest.raises(KeyboardInterrupt):
        lookup("example.com", probe=interrupt)
    with pytest.raises(SystemExit):
        lookup("example.com", probe=exit_now)


def _write_cert(tmp_path: Path) -> tuple[Path, Path, datetime]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    not_after = datetime(2027, 3, 15, tzinfo=UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, not_after


def test_probe_reads_localhost_leaf(tmp_path: Path) -> None:
    cert_path, key_path, not_after = _write_cert(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _addr = listener.accept()
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        leaf = probe_certificate("127.0.0.1", 5.0, port=port)
    finally:
        thread.join(timeout=5)
        listener.close()
    assert ("commonName", "localhost") in leaf.subject
    assert leaf.public_key == "RSA 2048"
    assert leaf.not_after == not_after
    assert leaf.tls_version in {"TLSv1.2", "TLSv1.3"}
    assert leaf.cipher
    assert leaf.fingerprint_sha256


class _FakeIO:
    def __enter__(self) -> _FakeIO:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form
        return b""


def test_empty_peer_certificate_and_sni(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    lookup_mod = sys.modules["lupaxa.ssl_info.lookup"]
    seen: list[str | None] = []
    addresses: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], *_args: object, **_kwargs: object) -> _FakeIO:
        addresses.append(address)
        return _FakeIO()

    def wrap(
        self: ssl.SSLContext,
        _sock: object,
        server_hostname: str | None = None,
    ) -> _FakeIO:
        seen.append(server_hostname)
        assert self.minimum_version == ssl.TLSVersion.TLSv1_2
        return _FakeIO()

    monkeypatch.setattr(lookup_mod.socket, "create_connection", connect)
    monkeypatch.setattr(lookup_mod.ssl.SSLContext, "wrap_socket", wrap)
    empty = lookup("example.com")
    assert empty.status == "error"
    assert empty.error == "no peer certificate"
    ip = lookup("127.0.0.1")
    assert ip.status == "error"
    assert seen == ["example.com", None]
    assert addresses == [("example.com", 443), ("127.0.0.1", 443)]
