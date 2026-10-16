"""SRP cipher suites (RFC 5054).

SRP is verified at the key-agreement level by the fork's Go round-trip test
(``srp_freetls_test.go``) and at the offer level here: the six AES suites are
registered and the ClientHello carries the RFC 5054 ``srp`` username extension
(type 12). OpenSSL 3.5.5's ``s_server -srpvfile`` path is deprecated and its
username lookup does not complete, so there is no local end-to-end SRP server to
negotiate against.
"""

from __future__ import annotations

import struct

import pytest

import freetls

TLS12 = 0x0303

SRP_SUITES = [
    0xC01D,  # TLS_SRP_SHA_WITH_AES_128_CBC_SHA
    0xC01E,  # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
    0xC01F,  # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
    0xC020,  # TLS_SRP_SHA_WITH_AES_256_CBC_SHA
    0xC021,  # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
    0xC022,  # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
]


def _client_hello_extensions(raw: bytes) -> dict[int, bytes]:
    # spec_raw returns the raw handshake message (not a TLS record).
    assert raw[0] == 0x01, "not a ClientHello handshake message"
    body = raw[4:]  # skip the handshake header
    i = 2 + 32
    sidlen = body[i]
    i += 1 + sidlen
    cslen = struct.unpack(">H", body[i : i + 2])[0]
    i += 2 + cslen
    complen = body[i]
    i += 1 + complen
    extlen = struct.unpack(">H", body[i : i + 2])[0]
    i += 2
    end = i + extlen
    out: dict[int, bytes] = {}
    while i < end:
        etype = struct.unpack(">H", body[i : i + 2])[0]
        elen = struct.unpack(">H", body[i + 2 : i + 4])[0]
        out[etype] = body[i + 4 : i + 4 + elen]
        i += 4 + elen
    return out


def test_srp_suites_registered():
    supported = set(freetls.engine.supported_ciphers())
    for suite in SRP_SUITES:
        assert suite in supported, f"SRP suite {suite:#06x} not registered"


def test_srp_username_extension_sent():
    from freetls import modes

    spec = modes.specific(ciphers=[0xC01D], vers_min=TLS12, vers_max=TLS12)
    spec.srp_username = "freetls"
    spec.srp_password = "secret"
    exts = _client_hello_extensions(freetls.engine.spec_raw(spec.to_engine()))
    assert 12 in exts, "srp username extension (type 12) missing"
    assert exts[12] == b"\x07freetls"


def test_srp_username_extension_absent_without_credentials():
    from freetls import modes

    spec = modes.specific(ciphers=[0xC01D], vers_min=TLS12, vers_max=TLS12)
    exts = _client_hello_extensions(freetls.engine.spec_raw(spec.to_engine()))
    assert 12 not in exts


def test_srp_negotiation_not_available_locally():
    """SRP has no local end-to-end server, so it is not negotiated here.

    OpenSSL 3.5.5 still ships the SRP ciphers and the ``srp`` username
    extension, but its deprecated ``s_server -srpvfile`` username lookup never
    resolves the user (its own ``s_client -srpuser`` also fails to complete), so
    a full SRP handshake cannot be driven locally. SRP correctness is covered by
    the fork's Go client/reference-server round-trip test
    (``srp_freetls_test.go``) and the offer-level checks above. This test exists
    so the limitation is explicit in the report rather than silently passing.
    """
    pytest.skip(
        "OpenSSL 3.5.5's deprecated s_server SRP app path does not complete; "
        "SRP is verified at the key-agreement level"
    )
