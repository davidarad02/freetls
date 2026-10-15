"""End-to-end tests for verification + Python certificate parity."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import freetls
from freetls import modes, verify

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from servers import LocalHTTPSServer  # noqa: E402


def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _make_ca_signed(d: Path):
    """Create a CA and a server cert signed by it (CA:FALSE, SAN localhost)."""
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    _openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-days",
        "2",
        "-nodes",
        "-subj",
        "/CN=Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    srv_key, srv_csr, srv_crt = d / "srv.key", d / "srv.csr", d / "srv.crt"
    _openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(srv_key),
        "-out",
        str(srv_csr),
        "-nodes",
        "-subj",
        "/CN=localhost",
    )
    ext = d / "ext.cnf"
    ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(srv_csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(srv_crt),
        "-days",
        "2",
        "-extfile",
        str(ext),
    )
    return str(ca_crt), str(srv_crt), str(srv_key)


@pytest.fixture()
def ca_server(tmp_path):
    ca_crt, srv_crt, srv_key = _make_ca_signed(tmp_path)
    with LocalHTTPSServer(srv_crt, srv_key) as srv:
        yield ca_crt, srv


def test_probe_matches_session(tls_server_13):
    spec = modes.baseline_spec(server_name="localhost")
    result = verify.probe(spec, "127.0.0.1", tls_server_13.port, "localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert result["ja4"] == s.ja4
        assert result["ja3"] == s.ja3
        assert result["ja4s"] == s.ja4s
        verify.assert_consistent(s)


def test_python_cert_parity_accepts_matching_ca(ca_server):
    ca_crt, srv = ca_server
    spec = modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", srv.port, server_hostname="localhost")
        assert s.state.peer_cert_der
        chain = verify.verify_peer_with_python(s, ca_crt, "localhost")
        assert len(chain) >= 1


def test_python_cert_parity_rejects_wrong_ca(ca_server, tmp_path):
    _ca, srv = ca_server
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_ca, _c, _k = _make_ca_signed(other_dir)
    spec = modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", srv.port, server_hostname="localhost")
        with pytest.raises(Exception):
            verify.verify_peer_with_python(s, other_ca, "localhost")


def test_engine_verification_succeeds_with_ca(ca_server):
    ca_crt, srv = ca_server
    spec = modes.baseline_spec(server_name="localhost", verify=True)
    spec.root_ca = ca_crt
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", srv.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"
