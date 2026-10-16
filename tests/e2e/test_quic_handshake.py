"""QUIC handshake, JA4q and session lifecycle against a local HTTP/3 server.

The server is built on upstream quic-go (not the uQUIC fork freetls ships), so
the client is exercised against an independent QUIC/TLS implementation.
"""

from __future__ import annotations

import pytest

from freetls import QUICSession, engine
from freetls.model import (
    TLS13,
    Extension,
    FingerprintSpec,
    QuicInitialSpec,
    TransportParameter,
)


def _transport_parameters() -> Extension:
    return Extension.quic_transport_parameters(
        TransportParameter.varint("max_idle_timeout", 30000),
        TransportParameter.varint("initial_max_data", 1048576),
        TransportParameter.varint("initial_max_stream_data_bidi_local", 262144),
        TransportParameter.varint("initial_max_stream_data_bidi_remote", 262144),
        TransportParameter.varint("initial_max_stream_data_uni", 262144),
        TransportParameter.varint("initial_max_streams_bidi", 100),
        TransportParameter.varint("initial_max_streams_uni", 100),
        TransportParameter.varint("max_udp_payload_size", 1472),
        TransportParameter.grease(4),
    )


def _quic_spec(server_name: str = "localhost") -> FingerprintSpec:
    return FingerprintSpec(
        ciphers=[0x1301, 0x1302, 0x1303],
        extensions=[
            Extension.sni(server_name),
            Extension.supported_versions(TLS13),
            Extension.supported_curves(0x001D, 0x0017),
            Extension.signature_algorithms(0x0403, 0x0804),
            Extension.key_share(0x001D),
            Extension.psk_key_exchange_modes(1),
            Extension.alpn("h3"),
            _transport_parameters(),
        ],
        vers_min=TLS13,
        vers_max=TLS13,
        server_name=server_name,
        quic=QuicInitialSpec(dcid_len=8, scid_len=0),
    )


def test_quic_handshake_and_ja4q(h3_server):
    session = QUICSession(_quic_spec())
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
        assert session.version() == "TLS1.3"
        assert session.client_hello[:1] == b"\x01"
        assert session.ja4q is not None and session.ja4q.startswith("q")
        assert session.ja4q_r is not None and session.ja4q_r.startswith("q")
        assert session.ja4q[1:] == session.fingerprints["ja4"][1:]
        # JA4Sq comes from the ServerHello the engine captured (QUIC has no TLS
        # record stream to tee).
        assert session.server_hello()[:1] == b"\x02"
        assert session.ja4sq is not None and session.ja4sq.startswith("q")
    finally:
        session.close()


def test_quic_client_hello_matches_offline_build(h3_server):
    """The reported JA4q must come from the bytes actually emitted.

    The raw ClientHello differs from the offline build by the
    initial_source_connection_id the engine injects into the transport
    parameters (RFC 9000 requires it); JA4q hashes extension *types*, so it must
    be identical either way.
    """
    from freetls.fingerprint import ja4_from_bytes

    spec = _quic_spec()
    offline = engine.spec_raw(spec.to_engine())
    session = QUICSession(spec)
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.client_hello[:1] == b"\x01"
        assert session.client_hello != offline  # ISCID injected by the engine
        assert ja4_from_bytes(session.client_hello, transport="q")["ja4"] == session.ja4q
        assert ja4_from_bytes(offline, transport="q")["ja4"] == session.ja4q
    finally:
        session.close()


def test_quic_session_is_freed(h3_server):
    before = engine.active_sessions()
    session = QUICSession(_quic_spec())
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    assert engine.active_sessions() == before + 1
    session.close()
    assert engine.active_sessions() == before


def test_quic_preset_handshake(h3_server):
    """A built-in uQUIC preset handshakes and reports its own JA4q."""
    spec = FingerprintSpec(quic_id="QUICFirefox_116", server_name="localhost")
    session = QUICSession(spec)
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
        assert session.ja4q is not None and session.ja4q.startswith("q")
    finally:
        session.close()


def test_quic_safe_mode_accepts_transport_parameters(h3_server):
    spec = _quic_spec()
    spec.safe = True
    session = QUICSession(spec)
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
    finally:
        session.close()


def test_quic_handshake_failure_is_reported():
    """A refused handshake raises and still frees the native session."""
    before = engine.active_sessions()
    spec = _quic_spec()
    session = QUICSession(spec)
    # Nothing is listening on this UDP port; QUIC will time out or fail.
    spec.timeout_ms = 1000
    with pytest.raises(Exception):
        session.connect("127.0.0.1", 1, timeout=1)
    session.close()
    assert engine.active_sessions() == before
