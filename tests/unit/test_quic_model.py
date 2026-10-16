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


def test_fake_transport_parameter_with_reserved_id_is_rejected():
    """A fake param whose id the QUIC stack handles must error, not abort the host."""
    from freetls import QUICSession

    spec = FingerprintSpec(
        ciphers=[0x1301, 0x1302, 0x1303],
        extensions=[
            Extension.alpn("h3"),
            Extension.quic_transport_parameters(
                TransportParameter.varint("max_idle_timeout", 30000),
                TransportParameter.fake(0x20, "aabbccdd"),
            ),
        ],
        vers_min=TLS13,
        vers_max=TLS13,
        quic=QuicInitialSpec(),
    )
    session = QUICSession(spec)
    try:
        with pytest.raises(Exception):
            session.connect("127.0.0.1", 9, timeout=2)
    finally:
        session.close()


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


def test_quic_datagrams_serialise_and_copy():
    spec = _spec(quic_datagrams=True)
    assert spec.to_engine()["quic_datagrams"] is True
    assert spec.copy().quic_datagrams is True
    assert "quic_datagrams" not in _spec().to_engine()


def test_quic_early_data_serialises_but_is_deferred():
    """quic_early_data is reserved for the deferred 0-RTT work (D13)."""
    spec = _spec(quic_early_data=True)
    assert spec.to_engine()["quic_early_data"] is True
    assert spec.copy().quic_early_data is True
    assert "quic_early_data" not in _spec().to_engine()


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


def test_quic_modes_build_and_are_quic():
    from freetls import modes
    from freetls.fingerprint import ja4_from_bytes

    specs = [
        modes.quic_baseline_spec(server_name="localhost"),
        modes.quic_specific(server_name="localhost"),
        modes.quic_partial_random(server_name="localhost", seed=1),
        modes.quic_true_random(server_name="localhost", seed=1),
    ]
    for spec in specs:
        engine_json = spec.to_engine()
        assert engine_json["transport"] == "quic"
        assert spec.vers_min == TLS13 and spec.vers_max == TLS13
        raw = engine.spec_raw(engine_json)
        assert ja4_from_bytes(raw, transport="q")["ja4"].startswith("q")


def test_quic_modes_safe_pass_validation():
    from freetls import modes

    for spec in (
        modes.quic_baseline_spec(server_name="localhost"),
        modes.quic_partial_random(server_name="localhost", seed=1, safe=True),
        modes.quic_true_random(server_name="localhost", seed=1, safe=True),
    ):
        spec.safe = True
        validate(spec)  # does not raise


def test_quic_baseline_mode_datagrams():
    from freetls import modes

    spec = modes.quic_baseline_spec(server_name="localhost", datagrams=True)
    assert spec.quic_datagrams is True
    assert spec.to_engine()["quic_datagrams"] is True
    assert modes.quic_baseline_spec().to_engine().get("quic_datagrams") is None
