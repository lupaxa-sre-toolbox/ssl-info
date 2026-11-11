<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="SRE Toolbox" />
  </a>
</p>

<h1 align="center">SSL Info</h1>

Show TLS leaf-certificate details for port 443.

`lupaxa-ssl-info` connects to each host, reads the leaf certificate the
server presents, and prints one labelled block per host. The handshake
requires TLS 1.2 or newer. Hostname matching and certificate trust are
not checked, so an expired, self-signed, or untrusted leaf is still
reported. The TCP port is always 443.

## Requirements

- Python 3.13 or newer
- Outbound TCP access to port 443

`cryptography` installs with the package.

## Install

```bash
pip install lupaxa-ssl-info
ssl-info --help
```

## CLI

```bash
ssl-info example.com example.org
ssl-info example.com,example.org
ssl-info --file hosts.txt
printf '%s\n' example.com example.org | ssl-info --file -
ssl-info --timeout 5 --sort not-after --order descending example.com example.org
python -m lupaxa.ssl_info --version
```

Pass hosts as separate arguments, or separate them with commas. International
names are converted to ASCII before the connection, and that form is the
block heading. IPv4 and IPv6 addresses are accepted. An `http://` or
`https://` scheme is removed, and the command warns that it is not needed.
A path, a port suffix, or any other non-host is invalid and is not connected.

`--file` reads one hostname per line. Blank lines and `#` comments are
ignored. `-` reads stdin. Repeat `--file` to combine lists. Hosts on the
command line are checked first, then hosts from each file.

`--timeout` is the TCP connect and TLS handshake timeout in seconds
(default `10`). It must be greater than `0`.

`--sort` orders the blocks by `host`, `issuer`, `not-before`, or
`not-after`. `--order` is `ascending` (the default) or `descending`.
`asc` and `desc` are accepted. Host and issuer order ignore case. Date
order uses the UTC timestamp. Blocks with no issuer or no date stay at
the end. Without `--sort`, blocks stay in the order the hosts were given.
`--order` without `--sort` exits `2`.

With no hosts, the command prints help and exits `2`.

## Output

Each host is a heading, then labelled lines. A blank line separates hosts.
Subject, issuer, version, serial, dates, signature, and public key are
always printed. A missing one of those is `—`. TLS version, cipher, ALPN,
fingerprints, and extensions are printed when they were found. A parsed
certificate does not print an extension it does not carry. Further
certificates from the handshake follow as `{host} chain 2`, then
`chain 3`, and so on.

```text
example.com
  Subject: CN=www.example.com, O=Example Inc, OU=Ops, C=US
  Issuer: CN=R3, O=Let's Encrypt
  Version: v3
  Serial: 4A3F2
  Not Before: 11th August 2026 00:00:00 UTC
  Not After: 9th November 2026 23:59:59 UTC
  Signature: sha256WithRSAEncryption
  Public Key: RSA 2048
  TLS Version: TLSv1.3
  Cipher: TLS_AES_128_GCM_SHA256 (128 bits)
  ALPN: h2
  Fingerprint SHA-256: 97:A0:F6:F6:27:4D:7E:05:5F:B5:E0:89:CE:F2:4A:E1:2F:75:14:07:8D:D2:FA:AB:8B:60:E8:D6:AF:CF:03:80
  Subject Alternative Names: DNS:example.com, DNS:www.example.com
  Key Usage: digital_signature, key_encipherment
  Extended Key Usage: serverAuth
  Basic Constraints: CA: false
  Authority Key Identifier: 14:2E:B3:17
  Subject Key Identifier: A1:B2:C3:D4
  Certificate Policies: 2.23.140.1.2.1
  CRL Distribution Points: URI:http://crl.example/example.crl
  Authority Information Access: OCSP: http://ocsp.example, CA Issuers: http://certs.example/ca.crt

slow.test
  Error: timed out

nope.invalid
  Error: Invalid Host
```

Subject and issuer are one distinguished-name line: `CN`, then `O`, then
every `OU`, then the remaining attributes. The serial is uppercase hex.
Dates are the UTC instant. The public key is one line, such as `RSA 2048`
or `ECDSA P-256`. An invalid host or a connection failure prints only the
heading and `Error:`. Each label is the display form of an `InfoResult`
attribute. The attribute names are listed under Result Fields.

## Exit Codes

| Code | When                                                                                 |
| :--- | :----------------------------------------------------------------------------------- |
| `0`  | Help, version, or every host returned a certificate                                  |
| `1`  | Any host is invalid                                                                  |
| `2`  | Usage failed, a file could not be read, no hosts were given, or a connection failed  |

When one host is invalid and another connection fails, the command exits `1`.

## Library

Import the public names from `lupaxa.ssl_info`.

| Name                | Role                                         |
| :------------------ | :------------------------------------------- |
| `lookup`            | Read one host and return an `InfoResult`     |
| `probe_certificate` | Open TLS on port 443 and return a `LeafCert` |
| `InfoResult`        | Formatted details for one host               |
| `LeafCert`          | Parsed leaf, before it is formatted          |
| `DEFAULT_TIMEOUT`   | `10.0` seconds                               |
| `get_version`       | The same text as `__version__`               |
| `__version__`       | The package version                          |

`lookup` checks the host, then reads the leaf. `timeout` is in seconds and
defaults to `DEFAULT_TIMEOUT`. It must be finite and greater than `0`, or
`lookup` raises `ValueError`. `probe` replaces the network call in tests.
The callable receives the normalized host and the timeout, and returns a
`LeafCert`.

```python
from lupaxa.ssl_info import lookup

result = lookup("example.com", timeout=10.0)
if result.status == "ok":
    print(result.subject, result.public_key, result.not_after)
else:
    print(result.status, result.error)
```

An invalid host is not connected. `status` is `invalid`, `error` is
`None`, and `host` is the stripped input. A connection failure sets
`status` to `error` and `error` to one line, such as `timed out` or
`no peer certificate`. `lookup` does not remove an `http://` or
`https://` scheme. The CLI does that before it calls `lookup`.

### Result Fields

`lookup` returns an `InfoResult`. Structured extension fields are `None`
when that extension is missing. `extensions` lists every extension that
was present, and that list is what the CLI prints for a parsed
certificate. `not_before` and `not_after` stay timezone-aware UTC
datetimes. The CLI formats them for display.

| Name                           | When    | Value                                                  |
| :----------------------------- | :------ | :----------------------------------------------------- |
| `host`                         | always  | ASCII hostname, or the stripped input when invalid     |
| `status`                       | always  | `ok`, `invalid`, or `error`                            |
| `subject`                      | `ok`    | One DN line, or `None` when the name is empty          |
| `issuer`                       | `ok`    | One DN line, or `None` when the name is empty          |
| `version`                      | `ok`    | Certificate version, such as `v3`                      |
| `serial`                       | `ok`    | Uppercase hex with no leading zeros                    |
| `not_before`                   | `ok`    | Timezone-aware UTC `datetime`                          |
| `not_after`                    | `ok`    | Timezone-aware UTC `datetime`                          |
| `signature`                    | `ok`    | Algorithm name, or a dotted OID                        |
| `public_key`                   | `ok`    | One line, such as `RSA 2048` or `ECDSA P-256`          |
| `tls_version`                  | found   | Negotiated TLS version, such as `TLSv1.3`              |
| `cipher`                       | found   | Cipher name and bit length                             |
| `alpn`                         | found   | Selected protocol, such as `h2`                        |
| `fingerprint_sha1`             | found   | Colon-separated SHA-1 of the certificate               |
| `fingerprint_sha256`           | found   | Colon-separated SHA-256 of the certificate             |
| `subject_alternative_names`    | `ok`    | `kind:value` pairs joined with commas, or `None`       |
| `key_usage`                    | `ok`    | Flag names joined with commas, or `None`               |
| `extended_key_usage`           | `ok`    | OID names joined with commas, or `None`                |
| `basic_constraints`            | `ok`    | `CA: true` or `CA: false`, plus path length, or `None` |
| `authority_key_identifier`     | `ok`    | Uppercase colon-separated bytes, or `None`             |
| `subject_key_identifier`       | `ok`    | Uppercase colon-separated bytes, or `None`             |
| `certificate_policies`         | `ok`    | Dotted OIDs joined with commas, or `None`              |
| `crl_distribution_points`      | `ok`    | URIs joined with commas, or `None`                     |
| `authority_information_access` | `ok`    | `method: location` pairs joined with commas, or `None` |
| `extensions`                   | found   | `(label, text)` pairs for every extension present      |
| `chain`                        | found   | Later certificates, headed `{host} chain 2` and so on  |
| `error`                        | `error` | One line. `None` for `ok` and `invalid`                |

Subject and issuer use the DN order shown in Output. The public key line is
`RSA {bits}`, `DSA {bits}`, `ECDSA P-256`, `ECDSA P-384`, `ECDSA P-521`,
`ECDSA {curve}` for any other curve, `Ed25519`, or `Ed448`. Key usage stays
in this order: `digital_signature`, `content_commitment`,
`key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`,
`crl_sign`, then `encipher_only` and `decipher_only` only when key agreement
is set. Alternative-name kinds are `DNS`, `IP`, `email`, `URI`, `DN`,
`RID`, and `other`.

### Leaf Fields

`probe_certificate(host, timeout, *, port=443)` returns a `LeafCert`. The
CLI has no port flag. Pass `port` only when a test binds another port.
These fields stay structured. `InfoResult` is their formatted form.

| Name                           | Value                                                |
| :----------------------------- | :--------------------------------------------------- |
| `subject`                      | `(oid name, text)` pairs, in certificate order       |
| `issuer`                       | The same shape as `subject`                          |
| `version`                      | Certificate version, such as `v3`                    |
| `serial_number`                | Integer. `InfoResult.serial` is the hex form         |
| `not_before`                   | Timezone-aware UTC `datetime`                        |
| `not_after`                    | Timezone-aware UTC `datetime`                        |
| `signature_algorithm`          | Algorithm name, or a dotted OID                      |
| `public_key`                   | The same text as `InfoResult.public_key`             |
| `fingerprint_sha1`             | Colon-separated SHA-1 of the certificate             |
| `fingerprint_sha256`           | Colon-separated SHA-256 of the certificate           |
| `tls_version`                  | Negotiated version, or `None` on a later certificate |
| `cipher`                       | Cipher name and bits, or `None`                      |
| `alpn`                         | Selected protocol, or `None`                         |
| `subject_alternative_names`    | `(kind, value)` pairs, or `None`                     |
| `key_usage`                    | Flag names, or `None`                                |
| `extended_key_usage`           | OID names, or `None`                                 |
| `basic_constraints`            | `(ca, path_length)`, or `None`                       |
| `authority_key_identifier`     | Key identifier bytes, or `None`                      |
| `subject_key_identifier`       | Key identifier bytes, or `None`                      |
| `certificate_policies`         | Dotted OIDs, or `None`                               |
| `crl_distribution_points`      | CRL URIs, or `None`                                  |
| `authority_information_access` | `(method, location)` pairs, or `None`                |
| `extensions`                   | `(label, text)` pairs for every extension present    |
| `chain`                        | Certificates sent after the leaf                     |

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
