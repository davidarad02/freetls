"""Build hook: compile the Go freetls engine and bundle it into the wheel.

The engine is a c-shared library (``libfreetls.so`` / ``.dylib`` / ``freetls.dll``)
loaded at runtime via cffi. Building it requires a Go toolchain (build time
only); the compiled library is bundled in the wheel, so end users do not need Go.

Go is discovered in this order:
  1. the ``FREETLS_GO`` environment variable,
  2. ``go`` on ``PATH``,
  3. common install locations (``~/.local/go``, ``/usr/local/go``, ``/opt/go``,
     Homebrew ``/opt/homebrew/bin``).

Set ``FREETLS_SKIP_NATIVE=1`` to build without the engine (e.g. for docs); the
resulting artifact will not perform TLS handshakes.

Set ``FREETLS_FULL=1`` to bundle the wide Route B engine (libcrypto linked
statically from ``native/third_party/openssl/libcrypto.a``, symbols hidden).
This requires ``make full`` (or an equivalent OpenSSL static build) beforehand;
without it, the default Go-only engine is bundled.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_py import build_py


LIB_NAMES = {
    "linux": "libfreetls.so",
    "darwin": "libfreetls.dylib",
    "windows": "freetls.dll",
}


def _find_go() -> str | None:
    env = os.environ.get("FREETLS_GO")
    if env:
        return env if os.path.exists(env) else shutil.which(env)
    found = shutil.which("go")
    if found:
        return found
    candidates = [
        os.path.expanduser("~/.local/go/bin/go"),
        "/usr/local/go/bin/go",
        "/opt/go/bin/go",
        "/opt/homebrew/bin/go",
        "/usr/local/bin/go",
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return None


class build_py_with_go(build_py):
    def run(self):
        here = os.path.dirname(os.path.abspath(__file__))
        native = os.path.join(here, "native")
        out_dir = os.path.join(here, "src", "freetls", "_lib")
        lib = LIB_NAMES.get(platform.system().lower(), "libfreetls.so")

        if os.environ.get("FREETLS_SKIP_NATIVE"):
            sys.stderr.write(
                "FREETLS_SKIP_NATIVE set; not bundling the native freetls engine.\n"
            )
        else:
            go = _find_go()
            if go is None:
                raise RuntimeError(
                    "Go toolchain not found. Install Go (https://go.dev/dl) and "
                    "retry, set FREETLS_GO=/path/to/go, or set FREETLS_SKIP_NATIVE=1 "
                    "to build without the native engine."
                )
            os.makedirs(out_dir, exist_ok=True)
            env = dict(os.environ)
            env.setdefault("GOPATH", os.path.expanduser("~/go"))
            env["CGO_ENABLED"] = "1"
            env["PATH"] = os.path.dirname(go) + os.pathsep + env.get("PATH", "")
            out_lib = os.path.join(out_dir, lib)

            if os.environ.get("FREETLS_FULL") == "1":
                # Ship the wide engine: libcrypto linked statically from the
                # OpenSSL submodule, symbols hidden. Requires `make full` to have
                # built native/third_party/openssl/libcrypto.a.
                openssl = os.path.join(native, "third_party", "openssl")
                libcrypto = os.path.join(openssl, "libcrypto.a")
                if not os.path.exists(libcrypto):
                    raise RuntimeError(
                        "FREETLS_FULL=1 but static OpenSSL is missing. Build it "
                        f"first (`make full`); expected {libcrypto}."
                    )
                env["CGO_CFLAGS"] = f"-I{openssl}/include"
                env["CGO_LDFLAGS"] = (
                    f"{libcrypto} -ldl -pthread -Wl,-Bsymbolic -Wl,--exclude-libs,ALL"
                )
                subprocess.run(
                    [
                        go,
                        "build",
                        "-tags",
                        "freetls_libcrypto freetls_static_openssl",
                        "-buildmode=c-shared",
                        "-o",
                        out_lib,
                        ".",
                    ],
                    cwd=native,
                    check=True,
                    env=env,
                )
            else:
                subprocess.run(
                    [go, "build", "-buildmode=c-shared", "-o", out_lib, "."],
                    cwd=native,
                    check=True,
                    env=env,
                )
        super().run()


cmdclass = {"build_py": build_py_with_go}

try:  # tag the wheel as platform-specific (it bundles a native library)
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

    class bdist_wheel(_bdist_wheel):
        def finalize_options(self):
            super().finalize_options()
            self.root_is_pure = False

    cmdclass["bdist_wheel"] = bdist_wheel
except Exception:  # pragma: no cover - wheel not importable
    pass


setup(cmdclass=cmdclass)
