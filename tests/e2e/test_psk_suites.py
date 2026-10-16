"""PSK cipher suites (RFC 4279/5487/5489): pure PSK, ECDHE-PSK, DHE-PSK, RSA-PSK.

Verifies that the wide engine completes each suite against a local
``openssl s_server`` configured with a pre-shared key. The wide engine is built
once per session and driven through a subprocess (see ``tests/_psk_client.py``).
The AES-CCM-8 suites carry a 64-bit tag, so the server runs at ``SECLEVEL=0``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
SRC = ROOT / "src"
CLIENT = Path(__file__).resolve().parents[1] / "_psk_client.py"
TLS12 = 0x0303
PSK_HEX = "0102030405060708090a0b0c0d0e0f10"
PSK_IDENTITY = "freetls"


def _find_go() -> str | None:
    env = os.environ.get("FREETLS_GO")
    if env:
        return env if os.path.exists(env) else shutil.which(env)
    found = shutil.which("go")
    if found:
        return found
    for cand in (
        os.path.expanduser("~/.local/go/bin/go"),
        "/usr/local/go/bin/go",
        "/opt/go/bin/go",
    ):
        if os.path.exists(cand):
            return cand
    return None


def _has_openssl_dev() -> bool:
    if shutil.which("pkg-config") is None:
        return False
    return (
        subprocess.run(
            ["pkg-config", "--exists", "libcrypto"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def wide_engine(tmp_path_factory) -> str:
    go = _find_go()
    if go is None:
        pytest.skip("Go toolchain not available")
    if not _has_openssl_dev():
        pytest.skip("OpenSSL development files (pkg-config libcrypto) not available")
    out = tmp_path_factory.mktemp("psk") / "libfreetls_libcrypto.so"
    env = dict(os.environ)
    env.setdefault("GOPATH", os.path.expanduser("~/go"))
    env["CGO_ENABLED"] = "1"
    subprocess.run(
        [go, "build", "-tags", "freetls_libcrypto", "-buildmode=c-shared", "-o", str(out), "."],
        cwd=NATIVE,
        check=True,
        env=env,
    )
    return str(out)


@pytest.fixture(scope="session")
def rsa_certs(tmp_path_factory) -> tuple[str, str]:
    d = tmp_path_factory.mktemp("psk-rsa")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


class _Server:
    def __init__(self, proc: subprocess.Popen, port: int):
        self.proc = proc
        self.port = port

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _start_server(certs: tuple[str, str] | None, cipher: str, *, groups: bool = False) -> _Server:
    port = _free_port()
    args = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-tls1_2",
        "-cipher",
        f"{cipher}@SECLEVEL=0",
        "-psk",
        PSK_HEX,
        "-psk_identity",
        PSK_IDENTITY,
        "-www",
        "-quiet",
    ]
    if groups:
        args += ["-groups", "ffdhe2048"]
    if certs is None:
        args.append("-nocert")
    else:
        args += ["-cert", certs[0], "-key", certs[1]]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return _Server(proc, port)
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("openssl s_server did not start")


def _run_client(lib: str, port: int, ciphers: list[int]) -> dict:
    env = dict(os.environ)
    env["FREETLS_LIB"] = lib
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    csv = ",".join(f"{c:04x}" for c in ciphers)
    proc = subprocess.run(
        [
            sys.executable,
            str(CLIENT),
            "127.0.0.1",
            str(port),
            csv,
            str(TLS12),
            str(TLS12),
            "localhost",
            PSK_IDENTITY,
            PSK_HEX,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        raise AssertionError(f"client crashed: {proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


# (suite id, openssl server cipher name)
PSK_SUITES = [
    (0x008C, "PSK-AES128-CBC-SHA"),
    (0x008D, "PSK-AES256-CBC-SHA"),
    (0x00A8, "PSK-AES128-GCM-SHA256"),
    (0x00A9, "PSK-AES256-GCM-SHA384"),
    (0x00AE, "PSK-AES128-CBC-SHA256"),
    (0x00AF, "PSK-AES256-CBC-SHA384"),
    (0xC06A, "PSK-ARIA128-GCM-SHA256"),
    (0xC06B, "PSK-ARIA256-GCM-SHA384"),
    (0xC094, "PSK-CAMELLIA128-SHA256"),
    (0xC095, "PSK-CAMELLIA256-SHA384"),
    (0xC0A4, "PSK-AES128-CCM"),
    (0xC0A5, "PSK-AES256-CCM"),
    (0xC0A8, "PSK-AES128-CCM8"),
    (0xC0A9, "PSK-AES256-CCM8"),
    (0xCCAB, "PSK-CHACHA20-POLY1305"),
]

ECDHE_PSK_SUITES = [
    (0xC035, "ECDHE-PSK-AES128-CBC-SHA"),
    (0xC036, "ECDHE-PSK-AES256-CBC-SHA"),
    (0xC037, "ECDHE-PSK-AES128-CBC-SHA256"),
    (0xC038, "ECDHE-PSK-AES256-CBC-SHA384"),
    (0xC09A, "ECDHE-PSK-CAMELLIA128-SHA256"),
    (0xC09B, "ECDHE-PSK-CAMELLIA256-SHA384"),
    (0xCCAC, "ECDHE-PSK-CHACHA20-POLY1305"),
]

DHE_PSK_SUITES = [
    (0x0090, "DHE-PSK-AES128-CBC-SHA"),
    (0x0091, "DHE-PSK-AES256-CBC-SHA"),
    (0x00AA, "DHE-PSK-AES128-GCM-SHA256"),
    (0x00AB, "DHE-PSK-AES256-GCM-SHA384"),
    (0x00B2, "DHE-PSK-AES128-CBC-SHA256"),
    (0x00B3, "DHE-PSK-AES256-CBC-SHA384"),
    (0xC06C, "DHE-PSK-ARIA128-GCM-SHA256"),
    (0xC06D, "DHE-PSK-ARIA256-GCM-SHA384"),
    (0xC096, "DHE-PSK-CAMELLIA128-SHA256"),
    (0xC097, "DHE-PSK-CAMELLIA256-SHA384"),
    (0xC0A6, "DHE-PSK-AES128-CCM"),
    (0xC0A7, "DHE-PSK-AES256-CCM"),
    (0xC0AA, "DHE-PSK-AES128-CCM8"),
    (0xC0AB, "DHE-PSK-AES256-CCM8"),
    (0xCCAD, "DHE-PSK-CHACHA20-POLY1305"),
]

RSA_PSK_SUITES = [
    (0x0094, "RSA-PSK-AES128-CBC-SHA"),
    (0x0095, "RSA-PSK-AES256-CBC-SHA"),
    (0x00AC, "RSA-PSK-AES128-GCM-SHA256"),
    (0x00AD, "RSA-PSK-AES256-GCM-SHA384"),
    (0x00B6, "RSA-PSK-AES128-CBC-SHA256"),
    (0x00B7, "RSA-PSK-AES256-CBC-SHA384"),
    (0xC06E, "RSA-PSK-ARIA128-GCM-SHA256"),
    (0xC06F, "RSA-PSK-ARIA256-GCM-SHA384"),
    (0xC098, "RSA-PSK-CAMELLIA128-SHA256"),
    (0xC099, "RSA-PSK-CAMELLIA256-SHA384"),
    (0xCCAE, "RSA-PSK-CHACHA20-POLY1305"),
]


@pytest.mark.parametrize("suite,name", PSK_SUITES, ids=[f"{s:04x}" for s, _ in PSK_SUITES])
def test_psk_suite_completes(wide_engine, suite, name):
    srv = _start_server(None, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite


@pytest.mark.parametrize(
    "suite,name", ECDHE_PSK_SUITES, ids=[f"{s:04x}" for s, _ in ECDHE_PSK_SUITES]
)
def test_ecdhe_psk_suite_completes(wide_engine, suite, name):
    srv = _start_server(None, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite


@pytest.mark.parametrize("suite,name", DHE_PSK_SUITES, ids=[f"{s:04x}" for s, _ in DHE_PSK_SUITES])
def test_dhe_psk_suite_completes(wide_engine, suite, name):
    srv = _start_server(None, name, groups=True)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite


@pytest.mark.parametrize("suite,name", RSA_PSK_SUITES, ids=[f"{s:04x}" for s, _ in RSA_PSK_SUITES])
def test_rsa_psk_suite_completes(wide_engine, rsa_certs, suite, name):
    srv = _start_server(rsa_certs, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite
