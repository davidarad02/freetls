"""Route B: libcrypto-backed cipher suites.

Verifies that the ``freetls_libcrypto`` engine completes the P1 suites
(ARIA-GCM and AES-CCM/CCM_8) against a local ``openssl s_server`` forced to each
suite. The wide engine is built once per session and exercised through a
subprocess (see ``tests/_route_b_client.py``).

TLS 1.3 CCM (``TLS_AES_128_CCM_SHA256``) is offered by the engine but cannot be
negotiated against the local OpenSSL/Go servers, which do not implement it; it is
covered at the AEAD/framing level by the Go tests in the fork and by an
offer-level check here.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
SRC = ROOT / "src"
CLIENT = Path(__file__).resolve().parents[1] / "_route_b_client.py"
PRESETS = Path(__file__).resolve().parents[1] / "_route_b_presets.py"

TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304


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
def libcrypto_engine(tmp_path_factory) -> str:
    go = _find_go()
    if go is None:
        pytest.skip("Go toolchain not available")
    if not _has_openssl_dev():
        pytest.skip("OpenSSL development files (pkg-config libcrypto) not available")
    out = tmp_path_factory.mktemp("routeb") / "libfreetls_libcrypto.so"
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
    d = tmp_path_factory.mktemp("routeb-rsa")
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


@pytest.fixture(scope="session")
def ec_certs(tmp_path_factory) -> tuple[str, str]:
    d = tmp_path_factory.mktemp("routeb-ec")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
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


def _start_server(certs: tuple[str, str], version: str, cipher: str, seclevel0: bool) -> _Server:
    cert, key = certs
    port = _free_port()
    cs = f"{cipher}:@SECLEVEL=0" if seclevel0 else cipher
    args = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-cert",
        cert,
        "-key",
        key,
        f"-{version}",
        "-cipher",
        cs,
        "-www",
        "-quiet",
    ]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return _Server(proc, port)
        except OSError:
            import time

            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("openssl s_server did not start")


def _run_client(lib: str, port: int, ciphers: list[int], vmin: int, vmax: int) -> dict:
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
            str(vmin),
            str(vmax),
            "localhost",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        raise AssertionError(f"client crashed: {proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


# (suite id, openssl server cipher name, cert kind, needs SECLEVEL=0)
TLS12_SUITES = [
    (0xC050, "ARIA128-GCM-SHA256", "rsa", False),
    (0xC051, "ARIA256-GCM-SHA384", "rsa", False),
    (0xC05C, "ECDHE-ECDSA-ARIA128-GCM-SHA256", "ec", False),
    (0xC05D, "ECDHE-ECDSA-ARIA256-GCM-SHA384", "ec", False),
    (0xC060, "ECDHE-ARIA128-GCM-SHA256", "rsa", False),
    (0xC061, "ECDHE-ARIA256-GCM-SHA384", "rsa", False),
    (0xC09C, "AES128-CCM", "rsa", False),
    (0xC09D, "AES256-CCM", "rsa", False),
    (0xC0A0, "AES128-CCM8", "rsa", True),
    (0xC0A1, "AES256-CCM8", "rsa", True),
    (0xC0AC, "ECDHE-ECDSA-AES128-CCM", "ec", False),
    (0xC0AD, "ECDHE-ECDSA-AES256-CCM", "ec", False),
    (0xC0AE, "ECDHE-ECDSA-AES128-CCM8", "ec", True),
    (0xC0AF, "ECDHE-ECDSA-AES256-CCM8", "ec", True),
    # P2 Camellia-CBC.
    (0x0041, "CAMELLIA128-SHA", "rsa", True),
    (0x0084, "CAMELLIA256-SHA", "rsa", True),
    (0x00BA, "CAMELLIA128-SHA256", "rsa", False),
    (0x00C0, "CAMELLIA256-SHA256", "rsa", False),
    (0xC072, "ECDHE-ECDSA-CAMELLIA128-SHA256", "ec", False),
    (0xC073, "ECDHE-ECDSA-CAMELLIA256-SHA384", "ec", False),
    (0xC076, "ECDHE-RSA-CAMELLIA128-SHA256", "rsa", False),
    (0xC077, "ECDHE-RSA-CAMELLIA256-SHA384", "rsa", False),
]


@pytest.mark.parametrize(
    "suite,name,certkind,seclevel0", TLS12_SUITES, ids=[f"{s:04x}" for s, *_ in TLS12_SUITES]
)
def test_tls12_libcrypto_suite_completes(
    libcrypto_engine, rsa_certs, ec_certs, suite, name, certkind, seclevel0
):
    certs = rsa_certs if certkind == "rsa" else ec_certs
    srv = _start_server(certs, "tls1_2", name, seclevel0)
    try:
        result = _run_client(libcrypto_engine, srv.port, [suite], TLS12, TLS12)
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite
    assert result["ja4"].startswith("t12")


@pytest.mark.parametrize(
    "version,vmin,vmax",
    [("tls1", TLS10, TLS10), ("tls1_1", TLS11, TLS11)],
    ids=["tls10", "tls11"],
)
def test_camellia_cbc_implicit_iv(libcrypto_engine, rsa_certs, version, vmin, vmax):
    """TLS 1.0/1.1 use the CBC implicit IV path."""
    srv = _start_server(rsa_certs, version, "CAMELLIA128-SHA", True)
    try:
        result = _run_client(libcrypto_engine, srv.port, [0x0041], vmin, vmax)
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["cipher_suite"] == 0x0041
    assert result["version"] in ("TLS1.0", "TLS1.1")


def test_default_engine_cannot_complete_aria(rsa_certs):
    """The default (Go-only) engine has no ARIA support, proving the widening."""
    lib = NATIVE / "libfreetls.so"
    if not lib.exists():
        pytest.skip("default engine not built")
    srv = _start_server(rsa_certs, "tls1_2", "ARIA128-GCM-SHA256", False)
    try:
        result = _run_client(str(lib), srv.port, [0xC050], TLS12, TLS12)
    finally:
        srv.stop()
    assert not result["ok"]


def test_tls13_ccm_offered(libcrypto_engine, rsa_certs):
    """TLS_AES_128_CCM_SHA256 is emitted in the ClientHello.

    No local server negotiates it, so we offer it alongside AES-128-GCM (which
    the server selects) and assert the CCM code point is present on the wire.
    """
    srv = _start_server(rsa_certs, "tls1_3", "ALL:@SECLEVEL=0", False)
    try:
        result = _run_client(libcrypto_engine, srv.port, [0x1304, 0x1301], TLS13, TLS13)
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.3"
    assert result["cipher_suite"] == 0x1301
    ch = bytes.fromhex(result["client_hello"])
    assert b"\x13\x04" in ch, "TLS_AES_128_CCM_SHA256 not offered in ClientHello"


def test_preset_ja4_parity(libcrypto_engine):
    """Presets must have identical JA4 with and without the libcrypto backend."""
    from freetls import engine, ja4_from_bytes

    samples = 6
    names = engine.preset_list()
    default_sets: dict[str, set[str]] = {}
    for name in names:
        seen: set[str] = set()
        for _ in range(samples):
            try:
                seen.add(ja4_from_bytes(engine.preset_raw(name))["ja4"])
            except Exception:  # noqa: BLE001
                break
        default_sets[name] = seen

    env = dict(os.environ)
    env["FREETLS_LIB"] = libcrypto_engine
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["FREETLS_PRESET_SAMPLES"] = str(samples)
    proc = subprocess.run(
        [sys.executable, str(PRESETS), *names],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    tagged_sets = {n: set(v) for n, v in json.loads(proc.stdout.strip().splitlines()[-1]).items()}

    # Compare only presets that are deterministic in *both* engines (a
    # nondeterministic preset's sampled set would differ by chance).
    compared = 0
    for name in names:
        d, w = default_sets.get(name, set()), tagged_sets.get(name, set())
        if len(d) == 1 and len(w) == 1:
            compared += 1
            assert d == w, f"{name}: default {d} != wide {w}"
    assert compared > 0, "no deterministic presets found to compare"
