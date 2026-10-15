"""P5 e2e: GREASE/padding control, response extras, and session resumption."""

from __future__ import annotations

import time

from freetls import modes
from freetls.fingerprint.parse import parse_client_hello
from freetls.model import TLS12, Extension


def _connect(server, spec, *, method="localhost"):
    from freetls import TLSSession

    s = TLSSession(spec)
    s.connect("127.0.0.1", server.port, server_hostname=method)
    s.do_handshake()
    return s


def _prime_ticket(session):
    session.sendall(b"GET / HTTP/1.0\r\n\r\n")
    try:
        session.recv(65536)
    except Exception:
        pass
    time.sleep(0.2)


def test_grease_padding_and_extras_on_the_wire(tls_server_13):
    spec = modes.baseline_spec(server_name="localhost")
    spec.extensions.append(Extension.padding(300))
    spec.extensions.append(Extension.record_size_limit(16385))
    spec.extensions.append(Extension.application_settings("h2"))
    modes.add_grease(spec, strategy="fixed")
    s = _connect(tls_server_13, spec)
    try:
        ch = parse_client_hello(s.client_hello)
        assert 0x0015 in ch.ext_types, "padding extension missing"
        assert 0x001C in ch.ext_types, "record_size_limit extension missing"
        assert 0x4469 in ch.ext_types, "ALPS extension missing"
        assert ch.ciphers[0] in modes.GREASE_VALUES, "GREASE cipher not first"
        padding = [e for e in ch.extensions if e.type == 0x0015][0]
        assert len(padding.data) == 300
    finally:
        s.close()


def test_grease_does_not_change_ja4(tls_server_13):
    plain = modes.baseline_spec(server_name="localhost")
    greased = modes.baseline_spec(server_name="localhost", grease=True, seed=3)
    s1 = _connect(tls_server_13, plain)
    ja4_plain = s1.ja4
    s1.close()
    s2 = _connect(tls_server_13, greased)
    ja4_greased = s2.ja4
    s2.close()
    assert ja4_plain == ja4_greased


def test_response_extras_default_empty(tls_server_13):
    s = _connect(tls_server_13, modes.baseline_spec(server_name="localhost"))
    try:
        assert s.ocsp_response == b""
        assert s.signed_certificate_timestamps == []
        assert s.peer_application_settings == b""
        assert s.did_resume is False
    finally:
        s.close()


def test_tls12_session_resumption(tls_server_12):
    spec = modes.baseline_spec(server_name="localhost", vers_min=TLS12, vers_max=TLS12)
    spec.extensions.append(Extension("session_ticket"))
    spec.session_cache = 32
    first = _connect(tls_server_12, spec)
    _prime_ticket(first)
    resumed_first = first.did_resume
    first.close()
    second = _connect(tls_server_12, spec)
    _prime_ticket(second)
    resumed_second = second.did_resume
    second.close()
    assert resumed_first is False
    assert resumed_second is True


def test_tls13_psk_resumption(tls_server_13):
    spec = modes.baseline_spec(server_name="127.0.0.1")
    spec.session_cache = 32
    spec.extensions.append(Extension.pre_shared_key())
    first = _connect(tls_server_13, spec, method="127.0.0.1")
    _prime_ticket(first)
    resumed_first = first.did_resume
    first.close()
    second = _connect(tls_server_13, spec, method="127.0.0.1")
    _prime_ticket(second)
    resumed_second = second.did_resume
    second.close()
    assert resumed_first is False
    assert resumed_second is True
