"""Unified per-suite client: negotiate one cipher suite and round-trip app data.

Used by ``tests/e2e/test_all_suites.py`` to exercise every locally-negotiable
suite against a purpose-built ``openssl s_server``. Loads the wide engine via
``FREETLS_LIB`` in a separate process (the cffi binding loads one engine per
process).

Usage:
  python tests/_suite_client.py <host> <port> <ciphers-hex-csv> <vmin> <vmax> \
      <name> <mode> <secret1> <secret2>

``mode`` is one of ``plain``, ``anon`` (ADH), ``psk`` (secret1=identity,
secret2=psk hex) or ``srp`` (secret1=username, secret2=password).
"""

from __future__ import annotations

import json
import sys

GROUPS = [0x001D, 0x0017, 0x0018, 0x0100, 0x0101]
SIGALGS = [
    0x0401,
    0x0501,
    0x0601,  # rsa_pkcs1_sha{256,384,512}
    0x0403,
    0x0503,
    0x0603,  # ecdsa_secp{256r1,384r1,521r1}_sha*
    0x0804,
    0x0805,
    0x0806,  # rsa_pss_rsae_sha{256,384,512}
    0x0202,  # dsa_sha256
]


def main() -> int:
    host, port, ciphers_csv, vmin, vmax, name, mode, s1, s2 = sys.argv[1:10]
    ciphers = [int(c, 16) for c in ciphers_csv.split(",") if c]

    import freetls

    freetls.set_default_verify(False)
    from freetls import TLSSession, modes

    spec = modes.specific(
        ciphers=ciphers,
        groups=GROUPS,
        sigalgs=SIGALGS,
        vers_min=int(vmin),
        vers_max=int(vmax),
        server_name=name or None,
    )
    if mode == "anon":
        spec.anonymous = True
    elif mode == "psk":
        spec.psk_identity = s1 or None
        spec.psk = s2 or None
    elif mode == "srp":
        spec.srp_username = s1 or None
        spec.srp_password = s2 or None

    out: dict[str, object] = {"ok": False}
    try:
        with TLSSession(spec) as s:
            s.connect(host, int(port), server_hostname=name or None)
            cipher = s.cipher()
            s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
            out = {
                "ok": True,
                "data_ok": b"HTTP/1.0 200" in data or b"HTTP/1.1 200" in data,
                "app_bytes": len(data),
                "version": s.state.version,
                "cipher_suite": s.state.cipher_suite,
                "cipher": cipher[0] if cipher else None,
            }
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
