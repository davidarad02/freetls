"""End-to-end: specify a fingerprint with named cipher suites / groups / sigalgs."""

from __future__ import annotations

import freetls
from freetls import Cipher, NamedGroup, SignatureScheme, modes


def test_specific_by_names_handshakes(tls_server_13):
    spec = modes.specific(
        ciphers=[
            Cipher.TLS_AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        groups=[NamedGroup.X25519, "secp256r1"],
        sigalgs=[SignatureScheme.RSA_PSS_RSAE_SHA256, "ecdsa_secp256r1_sha256"],
        server_name="localhost",
    )
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.fingerprints["ciphers"] == [0x1301, 0x1302, 0x1303]
        assert s.ja4.startswith("t13")
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        assert b"HTTP/1.0 200" in s.recv(256)


def test_baseline_accepts_named_ciphers(tls_server_13):
    spec = modes.baseline_spec(
        server_name="localhost",
        ciphers=["TLS_AES_128_GCM_SHA256", Cipher.TLS_AES_256_GCM_SHA384],
    )
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert 0x1301 in s.fingerprints["ciphers"]
