"""Shared pytest fixtures for freetls.

Provides:
- a self-hosted OpenSSL TLS server (any supported version),
- a one-time self-signed certificate,
- the native engine library (built on demand if Go is available),
- a capability-bearing tcpdump locator for pcap tests.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"


@pytest.fixture(scope="session", autouse=True)
def _default_verify_off():
    """The suite talks to self-signed local servers, so relax the secure default."""
    import freetls

    freetls.set_default_verify(False)
    yield
    freetls.set_default_verify(True)


def _lib_name() -> str:
    if sys.platform == "darwin":
        return "libfreetls.dylib"
    if sys.platform.startswith("win"):
        return "freetls.dll"
    return "libfreetls.so"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
        "/opt/homebrew/bin/go",
    ):
        if os.path.exists(cand):
            return cand
    return None


@pytest.fixture(scope="session", autouse=True)
def engine_lib() -> str:
    lib = NATIVE / _lib_name()
    if not lib.exists():
        # Build the default (wide) engine via the Makefile, which checks for
        # perl/make/gcc and the OpenSSL submodule.
        try:
            subprocess.run(["make", "native"], cwd=ROOT, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
            pytest.skip(f"could not build the wide engine ({exc}); run `make native`")
    os.environ["FREETLS_LIB"] = str(lib)
    return str(lib)


@pytest.fixture(scope="session")
def certs(tmp_path_factory) -> tuple[str, str]:
    d = tmp_path_factory.mktemp("certs")
    cert = d / "cert.pem"
    key = d / "key.pem"
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


class TLSServer:
    def __init__(self, proc: subprocess.Popen, port: int):
        self.proc = proc
        self.port = port

    def __enter__(self) -> TLSServer:
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def start_tls_server(
    certs: tuple[str, str], version: str = "tls1_3", seclevel0: bool = False
) -> TLSServer:
    cert, key = certs
    port = _free_port()
    args = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-cert",
        cert,
        "-key",
        key,
        "-www",
        "-quiet",
    ]
    if version != "auto":
        args.append(f"-{version}")
    if seclevel0:
        args += ["-cipher", "ALL:@SECLEVEL=0"]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait for the port to open
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return TLSServer(proc, port)
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("TLS server did not start")


@pytest.fixture()
def tls_server_13(certs):
    with start_tls_server(certs, "tls1_3") as srv:
        yield srv


@pytest.fixture()
def tls_server_12(certs):
    with start_tls_server(certs, "tls1_2", seclevel0=True) as srv:
        yield srv


@pytest.fixture()
def tls_server_11(certs):
    with start_tls_server(certs, "tls1_1", seclevel0=True) as srv:
        yield srv


@pytest.fixture()
def tls_server_10(certs):
    with start_tls_server(certs, "tls1", seclevel0=True) as srv:
        yield srv


@pytest.fixture()
def app_server(certs):
    """In-process Python ssl HTTPS server supporting the adapter matrix."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from servers import LocalHTTPSServer

    cert, key = certs
    with LocalHTTPSServer(cert, key) as srv:
        yield srv


@pytest.fixture()
def go_server(certs, tmp_path_factory):
    """A local Go net/http TLS server (HTTP/1.1 + HTTP/2)."""
    go = _find_go()
    if go is None:
        pytest.skip("Go toolchain not available")
    cert, key = certs
    src = Path(__file__).resolve().parent / "servers" / "go_https"
    binary = tmp_path_factory.mktemp("gobin") / "go_https"
    env = dict(os.environ)
    env.setdefault("GOPATH", os.path.expanduser("~/go"))
    subprocess.run([go, "build", "-o", str(binary), "."], cwd=src, check=True, env=env)
    port = _free_port()
    proc = subprocess.Popen(
        [str(binary), f"127.0.0.1:{port}", cert, key],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    try:
        yield TLSServer(proc, port)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture(scope="session")
def tcpdump_bin() -> str:
    """Locate a tcpdump capable of capturing loopback, else skip.

    Honours ``FREETLS_TCPDUMP``, then ``PATH``, then common locations
    (including the capability-bearing copy installed by ``make setup-caps``).
    """
    env = os.environ.get("FREETLS_TCPDUMP")
    candidates = []
    if env:
        candidates.append(env)
    # Prefer the capability-bearing copy installed by `make setup-caps`, since a
    # plain system tcpdump can exist but be unable to capture loopback.
    candidates.append(os.path.expanduser("~/.local/freetls-deps/bin/tcpdump"))
    which = shutil.which("tcpdump")
    if which:
        candidates.append(which)
    candidates += [
        "/usr/bin/tcpdump",
        "/usr/sbin/tcpdump",
        "/opt/homebrew/bin/tcpdump",
        "/usr/local/bin/tcpdump",
    ]
    for cand in candidates:
        if cand and os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    pytest.skip("no tcpdump available (install tcpdump and run `make setup-caps`)")
