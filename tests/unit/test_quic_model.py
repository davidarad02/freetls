"""The QUIC spec model: transport parameters, Initial shape, safe mode."""

from __future__ import annotations

import pytest

from freetls import engine
from freetls.errors import SpecError
from freetls.model import (
    TLS13,
    Extension,
    FingerprintSpec,
    QuicInitialSpec,
    TransportParameter,
)
from freetls.safety import effective_hello, validate


def _spec(**kw) -> FingerprintSpec:
    args: dict = {
        "ciphers": [0x1301, 0x1302, 0x1303],
        "extensions": [
            Extension.alpn("h3"),
            Extension.quic_transport_parameters(
                TransportParameter.varint("max_idle_timeout", 30000)
            ),
        ],
        "vers_min": TLS13,
        "vers_max": TLS13,
        "quic": QuicInitialSpec(),
    }
    args.update(kw)
    return FingerprintSpec(**args)


def test_transport_parameter_constructors():
    assert TransportParameter.varint("max_idle_timeout", 30).to_engine() == {
        "kind": "max_idle_timeout",
        "value": 30,
    }
    assert TransportParameter.grease(4).to_engine() == {"kind": "grease", "length": 4}
    assert TransportParameter.fake(0x4752, "00000001").to_engine() == {
        "kind": "fake",
        "id": 0x4752,
        "data": "00000001",
    }
    vi = TransportParameter.version_information(1, 0x0A0A0A0A, 1, legacy=True)
    assert vi.to_engine() == {
        "kind": "version_information",
        "value": 1,
        "versions": [0x0A0A0A0A, 1],
        "legacy": True,
    }
    assert TransportParameter.source_connection_id().to_engine() == {
        "kind": "initial_source_connection_id",
        "data": "",
    }
    assert TransportParameter.source_connection_id("0102").to_engine() == {
        "kind": "initial_source_connection_id",
        "data": "0102",
    }
    assert TransportParameter("disable_active_migration").to_engine() == {
        "kind": "disable_active_migration"
    }


def test_transport_parameter_validation():
    with pytest.raises(SpecError, match="unknown transport parameter kind"):
        TransportParameter("nope")
    with pytest.raises(SpecError, match="requires an id"):
        TransportParameter("fake")
    with pytest.raises(SpecError, match="non-zero"):
        TransportParameter.fake(0)
    with pytest.raises(SpecError, match="requires a value"):
        TransportParameter("max_idle_timeout")


def test_extension_serialises_transport_parameters():
    ext = Extension.quic_transport_parameters(
        TransportParameter.varint("initial_max_data", 1048576),
        TransportParameter.grease(2),
    )
    assert ext.to_engine() == {
        "type": "quic_transport_parameters",
        "transport_parameters": [
            {"kind": "initial_max_data", "value": 1048576},
            {"kind": "grease", "length": 2},
        ],
    }


def test_spec_copy_keeps_quic_state_independent():
    spec = _spec(quic=QuicInitialSpec(dcid_len=8, suppress_transport_parameters=[27]))
    clone = spec.copy()
    assert clone.to_engine() == spec.to_engine()
    clone.quic.suppress_transport_parameters.append(0x0F)
    assert spec.quic.suppress_transport_parameters == [27]
    assert type(clone.extensions[-1].transport_parameters[0]) is TransportParameter


def test_quic_spec_sets_transport_marker():
    engine_json = _spec().to_engine()
    assert engine_json["transport"] == "quic"
    assert engine_json["quic"]["dcid_len"] == 8


def test_quic_id_alone_marks_transport():
    engine_json = FingerprintSpec(quic_id="QUICFirefox_116").to_engine()
    assert engine_json["transport"] == "quic"
    assert engine_json["quic_id"] == "QUICFirefox_116"


def test_safe_mode_whitelists_transport_parameters():
    assert 0x0039 in engine.supported_extensions()


def test_safe_mode_accepts_a_quic_spec():
    spec = _spec()
    spec.safe = True
    validate(spec)  # does not raise
    assert effective_hello(spec)[:1] == b"\x01"


def test_quic_preset_list_and_build():
    ids = engine.quic_id_list()
    assert "QUICFirefox_116" in ids
    assert "QUICChrome_146_IPv4" in ids
    raw = engine.quic_id_raw("QUICChrome_146_IPv4", False, ["h3"])
    assert raw[:1] == b"\x01"
    from freetls.fingerprint import ja4_from_bytes

    assert ja4_from_bytes(raw, transport="q")["ja4"].startswith("q")


def test_quic_id_raw_unknown_preset_raises():
    with pytest.raises(SpecError, match="quic preset"):
        engine.quic_id_raw("QUICNope_1")
