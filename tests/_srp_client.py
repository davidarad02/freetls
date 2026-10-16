"""Standalone SRP client, run as a subprocess by the SRP suite tests.

Offers an SRP cipher suite together with the configured username/password so the
server can complete an SRP-6a key exchange. Loads the wide engine via
``FREETLS_LIB`` in a separate process (the cffi binding loads one engine per
process).

Usage:
  python tests/_srp_client.py <host> <port> <ciphers-hex-csv> <vmin> <vmax> \
      <name> <username> <password>
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    host, port, ciphers_csv, vmin, vmax, name, username, password = sys.argv[1:9]
    ciphers = [int(c, 16) for c in ciphers_csv.split(",") if c]

    import freetls

    freetls.set_default_verify(False)
    from freetls import TLSSession, modes

    spec = modes.specific(
        ciphers=ciphers,
        groups=[0x001D, 0x0017, 0x0018, 0x0100],
        sigalgs=[0x0403, 0x0402, 0x0503, 0x0202, 0x0804, 0x0401, 0x0501, 0x0601],
        vers_min=int(vmin),
        vers_max=int(vmax),
        server_name=name or None,
    )
    spec.srp_username = username or None
    spec.srp_password = password or None
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
                "ja4": s.ja4,
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
