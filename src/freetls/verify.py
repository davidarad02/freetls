"""Self-verification and optional Python certificate-verification parity.

freetls always self-verifies: the reported JA4/JA3/JA4S are recomputed from the
exact bytes that were emitted/received. This module also provides an optional
Python (`cryptography`) leaf-validation hook so callers can validate the peer
certificate independently of the Go engine's own x509 verification.
"""
from __future__ import annotations

from typing import Optional

from .errors import FingerprintError
from .fingerprint import ja3_from_bytes, ja4_from_bytes, ja4s_from_bytes


def fingerprints(session) -> dict:
    """Recompute JA4/JA3/JA4S from the session's captured handshake bytes."""
    out: dict = {}
    ch = getattr(session, "client_hello", b"")
    sh = getattr(session, "server_hello", b"")
    if ch:
        out.update(ja4_from_bytes(ch))
        out.update(ja3_from_bytes(ch))
    if sh:
        out.update(ja4s_from_bytes(sh))
    return out


def assert_consistent(session) -> dict:
    """Assert the session's reported fingerprints match the emitted bytes."""
    recomputed = fingerprints(session)
    for key in ("ja4", "ja3", "ja4s"):
        reported = getattr(session, key, None)
        if reported is None:
            continue
        if recomputed.get(key) != reported:
            raise FingerprintError(
                f"{key} mismatch: reported {reported!r} != emitted "
                f"{recomputed.get(key)!r}"
            )
    return recomputed


def probe(spec, host: str, port: int, server_hostname: Optional[str] = None) -> dict:
    """Connect to a local server and return its verified fingerprints."""
    from .session import TLSSession

    with TLSSession(spec) as s:
        s.connect(host, port, server_hostname=server_hostname or host)
        result = fingerprints(s)
        result["ja4"] = s.ja4
        result["ja3"] = s.ja3
        result["ja4s"] = s.ja4s
        result["version"] = s.state.version
    return result


# --------------------------------------------------------------------------- #
# Optional Python certificate verification (parity hook)
# --------------------------------------------------------------------------- #
def python_verify_leaf(
    leaf_der: bytes,
    cafile: str,
    server_hostname: str,
    now=None,
):
    """Validate a leaf certificate against a CA file using `cryptography`.

    Returns the verified chain. Raises on any verification failure. Requires the
    optional ``cryptography`` dependency.
    """
    try:
        from cryptography import x509
        from cryptography.x509 import verification
    except ImportError as exc:  # pragma: no cover
        raise FingerprintError(
            "the 'cryptography' package is required for python_verify_leaf"
        ) from exc

    with open(cafile, "rb") as fh:
        ca_pem = fh.read()
    store = verification.Store(x509.load_pem_x509_certificates(ca_pem))
    builder = verification.PolicyBuilder().store(store)
    if now is not None:
        builder = builder.time(now)
    verifier = builder.build_server_verifier(verification.DNSName(server_hostname))
    leaf = x509.load_der_x509_certificate(leaf_der)
    return verifier.verify(leaf, [])


def verify_peer_with_python(session, cafile: str, server_hostname: Optional[str] = None):
    """Run the Python parity hook against a live session's peer certificate."""
    der = session.state.peer_cert_der
    if not der:
        raise FingerprintError("no peer certificate captured")
    host = server_hostname or session.state.server_name
    return python_verify_leaf(der, cafile, host)
