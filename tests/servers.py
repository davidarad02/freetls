"""Local, in-process TLS/HTTP test servers.

These never touch the network beyond loopback. The app server implements the
HTTP behaviors exercised by the adapter matrix (POST echo, redirects, gzip,
chunked, cookies, header echo) and can serve any TLS version the local OpenSSL
supports.
"""
from __future__ import annotations

import gzip
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def _send(self, code, body=b"", headers=None, chunked=False, gzip_body=False):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "HEAD":
            return
        if gzip_body:
            body = gzip.compress(body)
        if chunked:
            for i in range(0, len(body), 8) or [0]:
                chunk = body[i:i + 8]
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(200, b"hello-root")
        elif self.path == "/gzip":
            body = b"gzipped-body-" * 20
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(gzip.compress(body))))
            self.end_headers()
            self.wfile.write(gzip.compress(body))
        elif self.path == "/chunked":
            self._send(200, b"chunked-body-" * 10, chunked=True)
        elif self.path == "/redirect":
            self._send(302, b"", headers={"Location": "/"})
        elif self.path == "/headers":
            payload = json.dumps({"headers": dict(self.headers)}).encode()
            self._send(200, payload, headers={"Content-Type": "application/json"})
        elif self.path == "/cookie":
            self._send(200, b"cookie-set",
                       headers={"Set-Cookie": "fl=1; Path=/"})
        else:
            self._send(404, b"not found")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._send(200, body)


class LocalHTTPSServer:
    def __init__(self, cert: str, key: str, max_version=ssl.TLSVersion.TLSv1_3,
                 min_version=ssl.TLSVersion.TLSv1_2):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = min_version
        self._ctx.maximum_version = max_version
        self._ctx.load_cert_chain(cert, key)
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._httpd.socket = self._ctx.wrap_socket(self._httpd.socket, server_side=True)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)
