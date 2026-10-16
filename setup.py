"""Build hook: compile the freetls engine(s) and bundle them into the wheel.

The default engine is the **wide** engine: Go + uTLS with a statically linked
OpenSSL ``libcrypto`` (EVP) backend, symbol-hidden so it never interposes on the
host process. A **Go-only** engine is also bundled so ``use_engine(Engine.GO)``
works after install. The engine is a c-shared library (``libfreetls.so`` /
``.dylib`` / ``freetls.dll``) loaded at runtime via cffi.

Building requires a Go toolchain, and — for the wide engine — ``perl``, ``make``,
``gcc`` and the OpenSSL source (the ``native/third_party/openssl`` git submodule,
fetched with ``--depth 1`` if missing). End users installing a wheel need none of
these. Go is discovered via ``FREETLS_GO``, then ``go`` on ``PATH``, then common
locations.

Environment:
  * ``FREETLS_NO_OPENSSL=1`` — build the Go-only engine only (no perl/make/OpenSSL
    needed); it is bundled as both the default and the ``_go`` engine.
  * ``FREETLS_GO`` — path to the Go toolchain.
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

OPENSSL_SUBMODULE = os.path.join("native", "third_party", "openssl")
OPENSSL_CONFIGURE = [
    "./Configure",
    "linux-x86_64",
    "no-shared",
    "no-tests",
    "no-zstd",
    "no-brotli",
    "no-ssl3",
    "no-comp",
    "-fPIC",
]
BUILD_JOBS = str(min(os.cpu_count() or 4, 18))


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


def _go_lib_name(default: str) -> str:
    stem, dot, ext = default.rpartition(".")
    return f"{stem}_go{dot}{ext}" if dot else f"{default}_go"


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        raise RuntimeError(
            f"the wide engine needs '{tool}' on PATH; install it, or set "
            "FREETLS_NO_OPENSSL=1 to build the Go-only engine."
        )


def _openssl_commit(openssl: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", openssl, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _stamp_matches(openssl: str) -> bool:
    """True if libcrypto.a was built from the current submodule commit + args."""
    stamp = os.path.join(openssl, ".freetls-built")
    libcrypto = os.path.join(openssl, "libcrypto.a")
    if not (os.path.exists(libcrypto) and os.path.exists(stamp)):
        return False
    args = " ".join(OPENSSL_CONFIGURE[1:])
    try:
        lines = open(stamp, encoding="utf-8").read().splitlines()
    except OSError:
        return False
    return len(lines) >= 2 and lines[0] == _openssl_commit(openssl) and lines[1] == args


def _ensure_libcrypto(here: str) -> str:
    """Return the path to a static libcrypto.a, building/fetching it if needed.

    Honours the same `.freetls-built` stamp as the Makefile, so a submodule
    commit or Configure-args change triggers a rebuild.
    """
    openssl = os.path.join(here, OPENSSL_SUBMODULE)
    libcrypto = os.path.join(openssl, "libcrypto.a")
    if _stamp_matches(openssl):
        return libcrypto

    if not os.path.exists(os.path.join(openssl, "Configure")):
        if os.path.exists(os.path.join(here, ".gitmodules")):
            sys.stderr.write(
                "freetls: fetching the OpenSSL submodule (shallow) for the wide engine...\n"
            )
            subprocess.run(
                [
                    "git",
                    "submodule",
                    "update",
                    "--init",
                    "--depth",
                    "1",
                    OPENSSL_SUBMODULE,
                ],
                cwd=here,
                check=True,
            )
        if not os.path.exists(os.path.join(openssl, "Configure")):
            raise RuntimeError(
                "OpenSSL source is missing and this is not a git checkout. Build "
                "the wide engine from a git checkout with submodules, or set "
                "FREETLS_NO_OPENSSL=1 to build the Go-only engine."
            )

    for tool in ("perl", "make", "gcc"):
        _require(tool)
    sys.stderr.write("freetls: building a static OpenSSL libcrypto.a for the wide engine...\n")
    subprocess.run(OPENSSL_CONFIGURE, cwd=openssl, check=True)
    subprocess.run(["make", f"-j{BUILD_JOBS}", "build_generated"], cwd=openssl, check=True)
    subprocess.run(["make", f"-j{BUILD_JOBS}", "libcrypto.a"], cwd=openssl, check=True)
    with open(os.path.join(openssl, ".freetls-built"), "w", encoding="utf-8") as fh:
        fh.write(f"{_openssl_commit(openssl)}\n{' '.join(OPENSSL_CONFIGURE[1:])}\n")
    return libcrypto


class build_py_with_go(build_py):
    def run(self):
        here = os.path.dirname(os.path.abspath(__file__))
        native = os.path.join(here, "native")
        out_dir = os.path.join(here, "src", "freetls", "_lib")
        default_lib = LIB_NAMES.get(platform.system().lower(), "libfreetls.so")
        go_lib = _go_lib_name(default_lib)

        go = _find_go()
        if go is None:
            raise RuntimeError(
                "Go toolchain not found. Install Go (https://go.dev/dl) and retry, "
                "or set FREETLS_GO=/path/to/go."
            )
        os.makedirs(out_dir, exist_ok=True)
        env = dict(os.environ)
        env.setdefault("GOPATH", os.path.expanduser("~/go"))
        env["CGO_ENABLED"] = "1"
        env["PATH"] = os.path.dirname(go) + os.pathsep + env.get("PATH", "")

        def build(out_name: str, tags: str | None, extra_env: dict | None = None) -> None:
            e = dict(env)
            if extra_env:
                e.update(extra_env)
            cmd = [go, "build"]
            if tags:
                cmd += ["-tags", tags]
            cmd += ["-buildmode=c-shared", "-o", os.path.join(out_dir, out_name), "."]
            subprocess.run(cmd, cwd=native, check=True, env=e)

        if os.environ.get("FREETLS_NO_OPENSSL") == "1":
            # Go-only engine, bundled as both the default and the alternate.
            build(default_lib, None)
            if go_lib != default_lib:
                shutil.copyfile(os.path.join(out_dir, default_lib), os.path.join(out_dir, go_lib))
        else:
            libcrypto = _ensure_libcrypto(here)
            openssl = os.path.join(here, OPENSSL_SUBMODULE)
            build(
                default_lib,
                "freetls_libcrypto freetls_static_openssl",
                {
                    "CGO_CFLAGS": f"-I{openssl}/include",
                    "CGO_LDFLAGS": (
                        f"{libcrypto} -ldl -pthread -Wl,-Bsymbolic -Wl,--exclude-libs,ALL"
                    ),
                },
            )
            build(go_lib, None)

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
