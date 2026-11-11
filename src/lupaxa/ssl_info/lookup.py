"""TLS leaf-certificate lookup for one host."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

DEFAULT_TIMEOUT = 10.0

Status = Literal["ok", "invalid", "error"]

_DN_SHORT = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
    "streetAddress": "STREET",
    "domainComponent": "DC",
    "userId": "UID",
    "emailAddress": "emailAddress",
    "surname": "SN",
    "givenName": "GN",
}
_DN_FIRST = ("commonName", "organizationName", "organizationalUnitName")
_KEY_USAGE = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)
_CURVE_LABELS = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}


@dataclass(frozen=True)
class LeafCert:
    """Leaf fields needed to format one detail block."""

    subject: tuple[tuple[str, str], ...]
    issuer: tuple[tuple[str, str], ...]
    version: str
    serial_number: int
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key: str
    subject_alternative_names: tuple[tuple[str, str], ...] | None = None
    key_usage: tuple[str, ...] | None = None
    extended_key_usage: tuple[str, ...] | None = None
    basic_constraints: tuple[bool, int | None] | None = None
    authority_key_identifier: bytes | None = None
    subject_key_identifier: bytes | None = None
    certificate_policies: tuple[str, ...] | None = None
    crl_distribution_points: tuple[str, ...] | None = None
    authority_information_access: tuple[tuple[str, str], ...] | None = None
    fingerprint_sha1: str | None = None
    fingerprint_sha256: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    extensions: tuple[tuple[str, str], ...] = ()
    chain: tuple[LeafCert, ...] = ()


@dataclass(frozen=True)
class InfoResult:
    """Formatted certificate details for one host."""

    host: str
    status: Status
    subject: str | None = None
    issuer: str | None = None
    version: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    signature: str | None = None
    public_key: str | None = None
    subject_alternative_names: str | None = None
    key_usage: str | None = None
    extended_key_usage: str | None = None
    basic_constraints: str | None = None
    authority_key_identifier: str | None = None
    subject_key_identifier: str | None = None
    certificate_policies: str | None = None
    crl_distribution_points: str | None = None
    authority_information_access: str | None = None
    error: str | None = None
    fingerprint_sha1: str | None = None
    fingerprint_sha256: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    extensions: tuple[tuple[str, str], ...] = ()
    chain: tuple[InfoResult, ...] = ()


Probe = Callable[[str, float], LeafCert]


def probe_certificate(host: str, timeout: float, *, port: int = 443) -> LeafCert:
    """Connect to ``host`` and return the presented leaf certificate.

    The handshake requires TLS 1.2 or newer. Hostname and certificate
    checks stay off, so an expired or untrusted leaf is still returned.

    Parameters
    ----------
    host:
        Normalized DNS name or IP address.
    timeout:
        Socket timeout in seconds for the TCP connect and the handshake.
    port:
        TCP port. The CLI always uses 443.

    Returns
    -------
    LeafCert
        Parsed leaf fields, handshake facts, and any further certificates
        the server sent. Extension fields are ``None`` when absent.

    Raises
    ------
    ValueError
        If ``timeout`` is not greater than 0.
    RuntimeError
        If the handshake yields no certificate bytes. The message is
        ``no peer certificate``.
    """
    _require_timeout(timeout)
    server_hostname = None if _is_ip(host) else host
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("no peer certificate")
            version = tls.version() if hasattr(tls, "version") else None
            cipher = _cipher_line(tls.cipher()) if hasattr(tls, "cipher") else None
            alpn = tls.selected_alpn_protocol() if hasattr(tls, "selected_alpn_protocol") else None
            chain_ders = tls.get_unverified_chain() if hasattr(tls, "get_unverified_chain") else ()
    leaf = _leaf_from_certificate(x509.load_der_x509_certificate(der))
    chain = tuple(
        _leaf_from_certificate(x509.load_der_x509_certificate(item))
        for item in chain_ders or ()
        if item != der
    )
    return replace(leaf, tls_version=version, cipher=cipher, alpn=alpn, chain=chain)


def lookup(
    host: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    probe: Probe | None = None,
) -> InfoResult:
    """Return the TLS leaf details of one host.

    Parameters
    ----------
    host:
        DNS name or IP address. International DNS names are converted to ASCII.
    timeout:
        Socket timeout in seconds. Must be greater than 0.
    probe:
        Callable ``(host, timeout) -> LeafCert``. Defaults to
        :func:`probe_certificate`.

    Returns
    -------
    InfoResult
        ``ok`` when a leaf certificate is read, ``invalid`` when the host
        is not a DNS name or IP address, or ``error`` when the probe fails.

    Raises
    ------
    ValueError
        If ``timeout`` is not greater than 0.
    """
    _require_timeout(timeout)
    try:
        normalized = _normalize_host(host)
    except ValueError:
        shown = host.strip() or host
        return InfoResult(shown, "invalid")
    query = probe or probe_certificate
    try:
        leaf = query(normalized, timeout)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        return InfoResult(normalized, "error", error=_error_text(exc))
    return _result_from_leaf(normalized, leaf)


def _enabled_key_usages(usage: x509.KeyUsage) -> tuple[str, ...] | None:
    names = [name for name in _KEY_USAGE if getattr(usage, name)]
    if usage.key_agreement:
        if usage.encipher_only:
            names.append("encipher_only")
        if usage.decipher_only:
            names.append("decipher_only")
    return tuple(names) or None


def _cipher_line(cipher: tuple[str, str, int] | None) -> str | None:
    if not cipher:
        return None
    name, _protocol, bits = cipher
    return f"{name} ({bits} bits)"


def _result_from_leaf(host: str, leaf: LeafCert) -> InfoResult:
    constraints = _basic_constraints(leaf.basic_constraints)
    chain = tuple(
        _result_from_leaf(f"{host} chain {index}", item)
        for index, item in enumerate(leaf.chain, start=2)
    )
    return InfoResult(
        host,
        "ok",
        subject=format_dn(leaf.subject),
        issuer=format_dn(leaf.issuer),
        version=leaf.version,
        serial=format(leaf.serial_number, "X"),
        not_before=_as_utc(leaf.not_before),
        not_after=_as_utc(leaf.not_after),
        signature=leaf.signature_algorithm,
        public_key=leaf.public_key,
        subject_alternative_names=_join_pairs(leaf.subject_alternative_names),
        key_usage=_join(leaf.key_usage),
        extended_key_usage=_join(leaf.extended_key_usage),
        basic_constraints=constraints,
        authority_key_identifier=_hex_bytes(leaf.authority_key_identifier),
        subject_key_identifier=_hex_bytes(leaf.subject_key_identifier),
        certificate_policies=_join(leaf.certificate_policies),
        crl_distribution_points=_join(leaf.crl_distribution_points),
        authority_information_access=_join_labeled(leaf.authority_information_access),
        fingerprint_sha1=leaf.fingerprint_sha1,
        fingerprint_sha256=leaf.fingerprint_sha256,
        tls_version=leaf.tls_version,
        cipher=leaf.cipher,
        alpn=leaf.alpn,
        extensions=leaf.extensions,
        chain=chain,
    )


def format_dn(pairs: tuple[tuple[str, str], ...]) -> str | None:
    """Return one DN line, or ``None`` when no attributes remain."""
    kept = [(name, value) for name, value in pairs if value.strip()]
    if not kept:
        return None
    ordered: list[tuple[str, str]] = []
    for oid in _DN_FIRST:
        ordered.extend(item for item in kept if item[0] == oid)
    ordered.extend(item for item in kept if item[0] not in _DN_FIRST)
    return ", ".join(f"{_DN_SHORT.get(name, name)}={_escape_dn(value)}" for name, value in ordered)


def _escape_dn(value: str) -> str:
    chars = list(value)
    start = 0
    end = len(chars) - 1
    while start <= end and chars[start] == " ":
        start += 1
    while end >= start and chars[end] == " ":
        end -= 1
    escaped: list[str] = []
    for index, char in enumerate(chars):
        if char == "\x00":
            escaped.append("\\00")
        elif char in '\\"+,;<>':
            escaped.append("\\" + char)
        elif char == "#" and index == 0:
            escaped.append("\\#")
        elif char == " " and (index < start or index > end):
            escaped.append("\\ ")
        else:
            escaped.append(char)
    return "".join(escaped)


def _basic_constraints(value: tuple[bool, int | None] | None) -> str | None:
    if value is None:
        return None
    ca, path_length = value
    text = f"CA: {str(ca).lower()}"
    if path_length is not None:
        text += f", Path Length: {path_length}"
    return text


def _join(items: tuple[str, ...] | None) -> str | None:
    if not items:
        return None
    return ", ".join(items)


def _join_pairs(items: tuple[tuple[str, str], ...] | None) -> str | None:
    if not items:
        return None
    return ", ".join(f"{kind}:{value}" for kind, value in items)


def _join_labeled(items: tuple[tuple[str, str], ...] | None) -> str | None:
    if not items:
        return None
    return ", ".join(f"{method}: {location}" for method, location in items)


def _hex_bytes(data: bytes | None) -> str | None:
    if not data:
        return None
    return ":".join(f"{byte:02X}" for byte in data)


def _oid_label(oid: x509.ObjectIdentifier) -> str:
    name = getattr(oid, "_name", None)
    dotted = oid.dotted_string
    if not isinstance(name, str) or name == dotted or name == "Unknown OID":
        return dotted
    return name


def _leaf_from_certificate(cert: x509.Certificate) -> LeafCert:
    return LeafCert(
        subject=_name_pairs(cert.subject),
        issuer=_name_pairs(cert.issuer),
        version=cert.version.name,
        serial_number=cert.serial_number,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_algorithm=_oid_label(cert.signature_algorithm_oid),
        public_key=_public_key_line(cert.public_key()),
        subject_alternative_names=_sans(cert),
        key_usage=_key_usage(cert),
        extended_key_usage=_extended_key_usage(cert),
        basic_constraints=_constraints(cert),
        authority_key_identifier=_authority_key_id(cert),
        subject_key_identifier=_subject_key_id(cert),
        certificate_policies=_policies(cert),
        crl_distribution_points=_crl_urls(cert),
        authority_information_access=_aia(cert),
        fingerprint_sha1=_fingerprint(cert, "sha1"),
        fingerprint_sha256=_fingerprint(cert, "sha256"),
        extensions=_extension_lines(cert),
    )


def _name_pairs(name: x509.Name) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for attr in name:
        text = str(attr.value).strip()
        if text:
            pairs.append((_oid_label(attr.oid), text))
    return tuple(pairs)


def _public_key_line(key: object) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        label = _CURVE_LABELS.get(key.curve.name, key.curve.name)
        return f"ECDSA {label}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def _extension[ET: x509.ExtensionType](cert: x509.Certificate, ext_class: type[ET]) -> ET | None:
    try:
        return cert.extensions.get_extension_for_class(ext_class).value
    except x509.ExtensionNotFound:
        return None


def _general_name(name: x509.GeneralName) -> tuple[str, str]:
    if isinstance(name, x509.DNSName):
        return ("DNS", name.value)
    if isinstance(name, x509.IPAddress):
        return ("IP", str(name.value))
    if isinstance(name, x509.RFC822Name):
        return ("email", name.value)
    if isinstance(name, x509.UniformResourceIdentifier):
        return ("URI", name.value)
    if isinstance(name, x509.DirectoryName):
        return ("DN", format_dn(_name_pairs(name.value)) or "")
    if isinstance(name, x509.RegisteredID):
        return ("RID", name.value.dotted_string)
    if isinstance(name, x509.OtherName):
        return ("other", f"{name.type_id.dotted_string}:{_other_name_value(name.value)}")
    return ("other", type(name).__name__)


def _other_name_value(value: bytes) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and text.isprintable():
        return text
    return ":".join(f"{byte:02X}" for byte in value)


def _sans(cert: x509.Certificate) -> tuple[tuple[str, str], ...] | None:
    ext = _extension(cert, x509.SubjectAlternativeName)
    if ext is None:
        return None
    pairs = [(kind, value) for kind, value in (_general_name(name) for name in ext) if value]
    return tuple(pairs) or None


def _key_usage(cert: x509.Certificate) -> tuple[str, ...] | None:
    ext = _extension(cert, x509.KeyUsage)
    if ext is None:
        return None
    return _enabled_key_usages(ext)


def _extended_key_usage(cert: x509.Certificate) -> tuple[str, ...] | None:
    ext = _extension(cert, x509.ExtendedKeyUsage)
    if ext is None:
        return None
    names = tuple(_oid_label(oid) for oid in ext)
    return names or None


def _constraints(cert: x509.Certificate) -> tuple[bool, int | None] | None:
    ext = _extension(cert, x509.BasicConstraints)
    if ext is None:
        return None
    return (ext.ca, ext.path_length)


def _authority_key_id(cert: x509.Certificate) -> bytes | None:
    ext = _extension(cert, x509.AuthorityKeyIdentifier)
    if ext is None:
        return None
    return ext.key_identifier or None


def _subject_key_id(cert: x509.Certificate) -> bytes | None:
    ext = _extension(cert, x509.SubjectKeyIdentifier)
    if ext is None:
        return None
    return ext.digest or None


def _policies(cert: x509.Certificate) -> tuple[str, ...] | None:
    ext = _extension(cert, x509.CertificatePolicies)
    if ext is None:
        return None
    oids = tuple(policy.policy_identifier.dotted_string for policy in ext)
    return oids or None


def _crl_urls(cert: x509.Certificate) -> tuple[str, ...] | None:
    ext = _extension(cert, x509.CRLDistributionPoints)
    if ext is None:
        return None
    urls: list[str] = []
    for point in ext:
        for name in point.full_name or ():
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return tuple(urls) or None


def _aia(cert: x509.Certificate) -> tuple[tuple[str, str], ...] | None:
    ext = _extension(cert, x509.AuthorityInformationAccess)
    if ext is None:
        return None
    entries: list[tuple[str, str]] = []
    for desc in ext:
        location = _aia_location(desc.access_location)
        if location:
            entries.append((_aia_method(desc.access_method), location))
    return tuple(entries) or None


def _aia_method(oid: x509.ObjectIdentifier) -> str:
    if oid == AuthorityInformationAccessOID.OCSP:
        return "OCSP"
    if oid == AuthorityInformationAccessOID.CA_ISSUERS:
        return "CA Issuers"
    return _oid_label(oid)


def _aia_location(name: x509.GeneralName) -> str:
    if isinstance(name, x509.UniformResourceIdentifier):
        return name.value
    if isinstance(name, x509.DirectoryName):
        return format_dn(_name_pairs(name.value)) or ""
    kind, value = _general_name(name)
    if not value:
        return ""
    return f"{kind}:{value}"


_EXTENSION_LABELS = {
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Names",
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: "Issuer Alternative Name",
    ExtensionOID.KEY_USAGE: "Key Usage",
    ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
    ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
    ExtensionOID.CERTIFICATE_POLICIES: "Certificate Policies",
    ExtensionOID.POLICY_MAPPINGS: "Policy Mappings",
    ExtensionOID.POLICY_CONSTRAINTS: "Policy Constraints",
    ExtensionOID.INHIBIT_ANY_POLICY: "Inhibit Any Policy",
    ExtensionOID.NAME_CONSTRAINTS: "Name Constraints",
    ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL Distribution Points",
    ExtensionOID.FRESHEST_CRL: "Freshest CRL",
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access",
    ExtensionOID.SUBJECT_INFORMATION_ACCESS: "Subject Information Access",
    ExtensionOID.TLS_FEATURE: "TLS Feature",
    ExtensionOID.OCSP_NO_CHECK: "OCSP No Check",
    ExtensionOID.PRECERT_POISON: "Precertificate Poison",
    ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: "Signed Certificate Timestamps",
    ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: (
        "Precertificate Signed Certificate Timestamps"
    ),
    ExtensionOID.PRIVATE_KEY_USAGE_PERIOD: "Private Key Usage Period",
    ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: "Subject Directory Attributes",
    ExtensionOID.MS_CERTIFICATE_TEMPLATE: "Microsoft Certificate Template",
    ExtensionOID.CRL_NUMBER: "CRL Number",
    ExtensionOID.DELTA_CRL_INDICATOR: "Delta CRL Indicator",
    ExtensionOID.ISSUING_DISTRIBUTION_POINT: "Issuing Distribution Point",
    ExtensionOID.ADMISSIONS: "Admissions",
}


def _fingerprint(cert: x509.Certificate, algorithm: str) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    if algorithm == "sha1":
        digest = hashlib.sha1(der, usedforsecurity=False).digest()
    else:
        digest = hashlib.new(algorithm, der).digest()
    return ":".join(f"{byte:02X}" for byte in digest)


def _extension_lines(cert: x509.Certificate) -> tuple[tuple[str, str], ...]:
    lines: list[tuple[str, str]] = []
    for ext in cert.extensions:
        label = _EXTENSION_LABELS.get(ext.oid, _oid_label(ext.oid))
        text = _format_extension_value(ext.value)
        if ext.critical:
            text = f"critical; {text}" if text else "critical"
        if text:
            lines.append((label, text))
    return tuple(lines)


def _format_extension_value(value: x509.ExtensionType) -> str:
    if isinstance(value, x509.KeyUsage):
        return _join(_enabled_key_usages(value)) or ""
    if isinstance(value, x509.ExtendedKeyUsage):
        return ", ".join(_oid_label(oid) for oid in value)
    if isinstance(value, x509.BasicConstraints):
        return _basic_constraints((value.ca, value.path_length)) or ""
    if isinstance(value, x509.SubjectKeyIdentifier):
        return _hex_bytes(value.digest) or ""
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return _format_authority_key_id(value)
    if isinstance(value, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        return _general_names(value)
    if isinstance(value, x509.CertificatePolicies):
        return ", ".join(_format_policy(policy) for policy in value)
    if isinstance(value, x509.PolicyConstraints):
        return _format_policy_constraints(value)
    if isinstance(value, x509.InhibitAnyPolicy):
        return f"skip {value.skip_certs}"
    if isinstance(value, x509.NameConstraints):
        return _format_name_constraints(value)
    if isinstance(value, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        points = (_format_distribution_point(point) for point in value)
        return "; ".join(text for text in points if text)
    if isinstance(value, (x509.AuthorityInformationAccess, x509.SubjectInformationAccess)):
        return _format_access_descriptions(value)
    if isinstance(value, x509.TLSFeature):
        return ", ".join(feature.name for feature in value)
    if isinstance(value, (x509.OCSPNoCheck, x509.PrecertPoison)):
        return "yes"
    if isinstance(
        value,
        (x509.SignedCertificateTimestamps, x509.PrecertificateSignedCertificateTimestamps),
    ):
        return "; ".join(_format_sct(stamp) for stamp in value)
    if isinstance(value, x509.PrivateKeyUsagePeriod):
        return _format_private_key_period(value)
    if isinstance(value, (x509.CRLNumber, x509.DeltaCRLIndicator)):
        return str(value.crl_number)
    if isinstance(value, x509.MSCertificateTemplate):
        return _format_ms_template(value)
    if isinstance(value, x509.UnrecognizedExtension):
        return _hex_bytes(value.value) or ""
    return _extension_bytes(value)


def _format_authority_key_id(value: x509.AuthorityKeyIdentifier) -> str:
    parts: list[str] = []
    key_id = _hex_bytes(value.key_identifier)
    if key_id:
        parts.append(key_id)
    issuer = _general_names(value.authority_cert_issuer)
    if issuer:
        parts.append(f"issuer {issuer}")
    if value.authority_cert_serial_number is not None:
        parts.append(f"serial {value.authority_cert_serial_number:X}")
    return ", ".join(parts)


def _format_policy(policy: x509.PolicyInformation) -> str:
    qualifiers = [_format_policy_qualifier(item) for item in policy.policy_qualifiers or ()]
    text = policy.policy_identifier.dotted_string
    shown = [item for item in qualifiers if item]
    if not shown:
        return text
    return f"{text} ({', '.join(shown)})"


def _format_policy_qualifier(qualifier: object) -> str:
    if isinstance(qualifier, str):
        return f"CPS: {qualifier}"
    if isinstance(qualifier, x509.UserNotice):
        parts: list[str] = []
        reference = qualifier.notice_reference
        if reference is not None:
            numbers = " ".join(str(number) for number in reference.notice_numbers)
            parts.append(" ".join(part for part in (reference.organization, numbers) if part))
        if qualifier.explicit_text:
            parts.append(qualifier.explicit_text)
        return "notice " + "; ".join(parts) if parts else "notice"
    return str(qualifier)


def _format_policy_constraints(value: x509.PolicyConstraints) -> str:
    parts: list[str] = []
    if value.require_explicit_policy is not None:
        parts.append(f"require explicit policy {value.require_explicit_policy}")
    if value.inhibit_policy_mapping is not None:
        parts.append(f"inhibit policy mapping {value.inhibit_policy_mapping}")
    return ", ".join(parts)


def _format_name_constraints(value: x509.NameConstraints) -> str:
    parts: list[str] = []
    permitted = _general_names(value.permitted_subtrees)
    excluded = _general_names(value.excluded_subtrees)
    if permitted:
        parts.append(f"permitted {permitted}")
    if excluded:
        parts.append(f"excluded {excluded}")
    return "; ".join(parts)


def _format_distribution_point(point: x509.DistributionPoint) -> str:
    parts: list[str] = []
    names = _general_names(point.full_name)
    if names:
        parts.append(names)
    if point.relative_name is not None:
        pairs = tuple(
            (_oid_label(attr.oid), str(attr.value).strip())
            for attr in point.relative_name
            if str(attr.value).strip()
        )
        relative = format_dn(pairs)
        if relative:
            parts.append(relative)
    if point.reasons:
        reasons = ", ".join(reason.name for reason in point.reasons)
        parts.append(f"reasons {reasons}")
    issuers = _general_names(point.crl_issuer)
    if issuers:
        parts.append(f"issuer {issuers}")
    return ", ".join(parts)


def _format_access_descriptions(
    value: x509.AuthorityInformationAccess | x509.SubjectInformationAccess,
) -> str:
    parts: list[str] = []
    for desc in value:
        location = _aia_location(desc.access_location)
        if location:
            parts.append(f"{_aia_method(desc.access_method)}: {location}")
    return ", ".join(parts)


def _format_sct(stamp: object) -> str:
    moment = getattr(stamp, "timestamp", None)
    if not isinstance(moment, datetime):
        return str(stamp)
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    millis = moment.microsecond // 1000
    when = moment.strftime("%Y-%m-%d %H:%M:%S") + f".{millis:03d} UTC"
    log_id = _hex_bytes(getattr(stamp, "log_id", None)) or ""
    entry = getattr(getattr(stamp, "entry_type", None), "name", "")
    return " ".join(part for part in (when, entry, f"log {log_id}" if log_id else "") if part)


def _format_private_key_period(value: x509.PrivateKeyUsagePeriod) -> str:
    parts: list[str] = []
    if value.not_before is not None:
        parts.append(f"not before {value.not_before.isoformat()}")
    if value.not_after is not None:
        parts.append(f"not after {value.not_after.isoformat()}")
    return ", ".join(parts)


def _format_ms_template(value: x509.MSCertificateTemplate) -> str:
    parts = [_oid_label(value.template_id)]
    if value.major_version is not None:
        parts.append(f"major {value.major_version}")
    if value.minor_version is not None:
        parts.append(f"minor {value.minor_version}")
    return ", ".join(parts)


def _general_names(names: Iterable[x509.GeneralName] | None) -> str:
    if not names:
        return ""
    return ", ".join(
        f"{kind}:{value}" for kind, value in (_general_name(name) for name in names) if value
    )


def _extension_bytes(value: x509.ExtensionType) -> str:
    public_bytes = getattr(value, "public_bytes", None)
    if not callable(public_bytes):
        return type(value).__name__
    try:
        data = public_bytes()
    except TypeError:
        return type(value).__name__
    if isinstance(data, bytes):
        return _hex_bytes(data) or type(value).__name__
    return type(value).__name__


def _normalize_host(host: str) -> str:
    raw = host.strip()
    if not raw:
        raise ValueError("host must be a hostname")
    if raw.startswith("[") and raw.endswith("]"):
        try:
            v6_addr = ipaddress.IPv6Address(raw[1:-1])
        except ValueError as exc:
            raise ValueError("host must be a hostname") from exc
        if v6_addr.scope_id is not None:
            raise ValueError("host must be a hostname")
        return str(v6_addr)
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id is not None:
            raise ValueError("host must be a hostname")
        return str(addr)
    value = raw.lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or any(char in value for char in " /\\:@?#"):
        raise ValueError("host must be a hostname")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("host must be a hostname") from exc
    labels = ascii_name.split(".")
    if not labels or any(not _is_label(label) for label in labels):
        raise ValueError("host must be a hostname")
    if len(ascii_name) > 253:
        raise ValueError("host must be a hostname")
    return ascii_name


def _is_label(label: str) -> bool:
    if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
        return False
    return all(char.isalnum() or char == "-" for char in label)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _require_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be greater than 0")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    return float(timeout)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _error_text(exc: BaseException) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    return " ".join(text.split())
