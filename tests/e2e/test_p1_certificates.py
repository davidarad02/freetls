"""P1 certificate suite: chain, verify options, pinning, mTLS."""

from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import freetls
from freetls import modes
from freetls.errors import HandshakeError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from servers import LocalHTTPSServer  # noqa: E402


def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


class PKI:
    def __init__(self, d: Path):
        self.ca = d / "ca.crt"
        self.server_crt = d / "srv.crt"
        self.server_key = d / "srv.key"
        self.client_crt = d / "cli.crt"
        self.client_key = d / "cli.key"
        self._make(d)

    def _make(self, d: Path) -> None:
        ca_key = d / "ca.key"
        _openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(ca_key),
            "-out",
            str(self.ca),
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
        self._sign(
            d,
            "srv",
            "localhost",
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
        )
        self._sign(
            d,
            "cli",
            "client",
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=clientAuth\n",
        )

    def _sign(self, d: Path, name: str, cn: str, ext: str) -> None:
        key = d / f"{name}.key"
        csr = d / f"{name}.csr"
        crt = d / f"{name}.crt"
        extf = d / f"{name}.ext"
        extf.write_text(ext)
        _openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-nodes",
            "-subj",
            f"/CN={cn}",
        )
        _openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(self.ca),
            "-CAkey",
            str(d / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(crt),
            "-days",
            "2",
            "-extfile",
            str(extf),
        )


@pytest.fixture()
def pki(tmp_path):
    return PKI(tmp_path)


@pytest.fixture()
def tls_server(pki):
    with LocalHTTPSServer(str(pki.server_crt), str(pki.server_key)) as srv:
        yield srv


@pytest.fixture()
def mtls_server(pki):
    with LocalHTTPSServer(str(pki.server_crt), str(pki.server_key), client_ca=str(pki.ca)) as srv:
        yield srv


def _connect(port, spec, hostname="localhost"):
    s = freetls.TLSSession(spec)
    s.connect("127.0.0.1", port, server_hostname=hostname)
    return s


def test_verify_with_ca_and_chain(pki, tls_server):
    spec = modes.baseline_spec(server_name="localhost")
    spec.verify = True
    spec.root_ca = str(pki.ca)
    spec.system_roots = False
    with _connect(tls_server.port, spec) as s:
        chain = s.peer_chain()
        assert len(chain) >= 1
        der = s.getpeercert(binary_form=True)
        assert isinstance(der, bytes) and der == chain[0]
        info = s.getpeercert()
        assert any(k == "commonName" for k, _ in info["subject"][0])


def test_check_hostname_mismatch_and_override(pki, tls_server):
    base = modes.baseline_spec(server_name="wrong.example")
    base.verify = True
    base.root_ca = str(pki.ca)
    base.system_roots = False
    # Wrong hostname with check_hostname=True fails.
    with pytest.raises(HandshakeError):
        _connect(tls_server.port, base.copy(), hostname="wrong.example")
    # check_hostname=False verifies the chain but skips the name.
    s = base.copy()
    s.check_hostname = False
    with _connect(tls_server.port, s, hostname="wrong.example") as sess:
        assert sess.ja4.startswith("t13")


def test_certificate_pinning(pki, tls_server):
    spec = modes.baseline_spec(server_name="localhost")
    spec.verify = True
    spec.root_ca = str(pki.ca)
    spec.system_roots = False
    # Learn the real pin, then pin it.
    with _connect(tls_server.port, spec.copy()) as s:
        pin = base64.b64encode(hashlib.sha256(s.peer_chain()[0]).digest()).decode()
    spec.pinned_sha256 = [pin]
    with _connect(tls_server.port, spec.copy()) as s:
        assert s.ja4.startswith("t13")
    bad = spec.copy()
    bad.pinned_sha256 = [base64.b64encode(b"\x00" * 32).decode()]
    with pytest.raises(HandshakeError):
        _connect(tls_server.port, bad)


def test_verify_with_cadata_and_ca_dir(pki, tls_server, tmp_path):
    ca_pem = Path(pki.ca).read_text()
    spec = modes.baseline_spec(server_name="localhost")
    spec.verify = True
    spec.system_roots = False
    spec.cadata = ca_pem
    with _connect(tls_server.port, spec) as s:
        assert s.ja4.startswith("t13")
    ca_dir = tmp_path / "cadir"
    ca_dir.mkdir()
    (ca_dir / "ca.pem").write_text(ca_pem)
    spec2 = modes.baseline_spec(server_name="localhost")
    spec2.verify = True
    spec2.system_roots = False
    spec2.ca_dir = str(ca_dir)
    with _connect(tls_server.port, spec2) as s:
        assert s.ja4.startswith("t13")


def test_mtls_client_certificate(pki, mtls_server):
    spec = modes.baseline_spec(server_name="localhost")
    spec.verify = True
    spec.root_ca = str(pki.ca)
    spec.system_roots = False
    spec.client_cert = str(pki.client_crt)
    spec.client_key = str(pki.client_key)
    with _connect(mtls_server.port, spec) as s:
        result = freetls.verify.assert_consistent(s)
        assert result["ja4"].startswith("t13")
    # Without a client cert the server rejects the handshake. Use TLS 1.2 so the
    # failure surfaces during the handshake (TLS 1.3 verifies it after the
    # client's Finished, so the client may not see it).
    no_cert = modes.baseline_spec(
        server_name="localhost", vers_min=freetls.TLS12, vers_max=freetls.TLS12
    )
    no_cert.verify = True
    no_cert.root_ca = str(pki.ca)
    no_cert.system_roots = False
    with pytest.raises(HandshakeError):
        _connect(mtls_server.port, no_cert)
