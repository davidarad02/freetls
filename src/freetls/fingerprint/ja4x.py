"""JA4X: X.509 certificate structure fingerprint (report-only).

``JA4X = <issuer>_<subject>_<extensions>`` where each part is the first 12 hex
characters of a SHA-256 over a comma-joined list. The issuer/subject parts hash
the ordered list of RDN OID-hex codes; the extensions part hashes the ordered
list of extension OID-hex codes. Follows the FoxIO JA4X definition.
"""

from __future__ import annotations

from hashlib import sha256

__all__ = ["oid_to_hex", "ja4x", "ja4x_from_cert"]


def _encode_variable_length_quantity(v: int) -> list[int]:
    m = 0x00
    out: list[int] = []
    while v >= 0x80:
        out.insert(0, (v & 0x7F) | m)
        v = v >> 7
        m = 0x80
    out.insert(0, v | m)
    return out


def oid_to_hex(oid: str) -> str:
    """Encode a dotted OID (``"2.5.4.3"``) as its DER content hex (``"550403"``).

    A value that already looks like hex is returned unchanged.
    """
    text = str(oid)
    if "." not in text:
        return text.lower()
    parts = [int(x) for x in text.split(".")]
    body = [parts[0] * 40 + parts[1]]
    for n in parts[2:]:
        body.extend(_encode_variable_length_quantity(n))
    body.insert(0, len(body))
    body.insert(0, 0x06)
    return "".join(f"{b:02x}" for b in body)[4:]


def _sha_encode(values: list[str]) -> str:
    return sha256(",".join(values).encode("utf8")).hexdigest()[:12]


def ja4x(issuer_oids, subject_oids, extension_oids) -> str:
    """Compute the JA4X value from ordered OID lists (dotted or hex)."""
    issuer = _sha_encode([oid_to_hex(o) for o in issuer_oids])
    subject = _sha_encode([oid_to_hex(o) for o in subject_oids])
    extensions = _sha_encode([oid_to_hex(o) for o in extension_oids])
    return f"{issuer}_{subject}_{extensions}"


def ja4x_from_cert(cert) -> str:
    """Compute JA4X directly from a DER/PEM certificate (needs ``cryptography``)."""
    from cryptography import x509

    if isinstance(cert, str):
        cert = cert.encode()
    if cert.lstrip().startswith(b"-----BEGIN"):
        parsed = x509.load_pem_x509_certificate(cert)
    else:
        parsed = x509.load_der_x509_certificate(cert)
    issuer = [a.oid.dotted_string for rdn in parsed.issuer.rdns for a in rdn]
    subject = [a.oid.dotted_string for rdn in parsed.subject.rdns for a in rdn]
    extensions = [e.oid.dotted_string for e in parsed.extensions]
    return ja4x(issuer, subject, extensions)
