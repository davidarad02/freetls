"""Shared QUIC ClientHello builder for the HTTP/3 e2e tests."""

from __future__ import annotations

from freetls.model import (
    TLS13,
    Extension,
    FingerprintSpec,
    QuicInitialSpec,
    TransportParameter,
)


def quic_spec(
    *,
    ciphers=None,
    server_name: str = "localhost",
    datagrams: bool = False,
) -> FingerprintSpec:
    """A minimal, realistic QUIC ClientHello spec for the local h3 test server."""
    return FingerprintSpec(
        ciphers=list(ciphers) if ciphers is not None else [0x1301, 0x1302, 0x1303],
        extensions=[
            Extension.sni(server_name),
            Extension.supported_versions(TLS13),
            Extension.supported_curves(0x001D, 0x0017),
            Extension.signature_algorithms(0x0403, 0x0804),
            Extension.key_share(0x001D),
            Extension.psk_key_exchange_modes(1),
            Extension.alpn("h3"),
            Extension.quic_transport_parameters(
                TransportParameter.varint("max_idle_timeout", 30000),
                TransportParameter.varint("initial_max_data", 1048576),
                TransportParameter.varint("initial_max_stream_data_bidi_local", 262144),
                TransportParameter.varint("initial_max_stream_data_bidi_remote", 262144),
                TransportParameter.varint("initial_max_stream_data_uni", 262144),
                TransportParameter.varint("initial_max_streams_bidi", 100),
                TransportParameter.varint("initial_max_streams_uni", 100),
                TransportParameter.varint("max_udp_payload_size", 1472),
                TransportParameter.grease(4),
            ),
        ],
        vers_min=TLS13,
        vers_max=TLS13,
        server_name=server_name,
        quic=QuicInitialSpec(dcid_len=8, scid_len=0),
        quic_datagrams=datagrams,
    )
