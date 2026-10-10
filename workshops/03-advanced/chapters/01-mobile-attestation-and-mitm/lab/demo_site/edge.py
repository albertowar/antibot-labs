"""
W3 Ch1 — TLS edge with JA4 (reused from W2 Ch5/Ch9)

Serves the Flask store over HTTPS and fingerprints every TLS connection.

In production, TLS ends at a CDN or load balancer, which computes JA4 and
passes it to the app in a header it controls. In the lab, this module plays
that role:

  1. accept the TCP connection
  2. peek (MSG_PEEK) at the ClientHello bytes without consuming them
  3. compute JA4 (ja4.py)
  4. do the real TLS handshake on the same socket
  5. hand the connection to Werkzeug, which puts the JA4 into the WSGI
     environ as "lab.ja4"

The fingerprint travels in the WSGI environ, not in a header, so a client
cannot spoof it. When you move this pattern behind a real proxy, strip the
JA4 header at the edge and set it yourself. Otherwise any client can send
"X-JA4: <Chrome's value>".

Trade-off: the server offers only http/1.1 in ALPN. Real browsers offer h2
and fall back, which leaves JA4 unchanged (it records what the client
*offers*) but hides HTTP/2 SETTINGS fingerprints. Those are discussed in
the slides, not measured in the lab.
"""

import socket
import ssl
import time

from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler

from ja4 import NotClientHello, ja4_from_bytes, parse_client_hello, record_length

PEEK_TIMEOUT_S = 3.0
MAX_RECORD = 16384 + 5


def peek_client_hello(sock):
    """Wait until the whole first TLS record is in the socket buffer; return it unread."""
    deadline = time.monotonic() + PEEK_TIMEOUT_S
    sock.settimeout(PEEK_TIMEOUT_S)
    data = b""
    while time.monotonic() < deadline:
        data = sock.recv(MAX_RECORD, socket.MSG_PEEK)
        if not data:
            raise NotClientHello("connection closed before ClientHello")
        needed = record_length(data)
        if needed is not None and len(data) >= needed:
            return data[:needed]
        time.sleep(0.005)  # the rest of a large (post-quantum) ClientHello is still in flight
    raise NotClientHello("timed out waiting for ClientHello")


class LabRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        environ["wsgi.url_scheme"] = "https"
        environ["lab.ja4"] = getattr(self.connection, "lab_ja4", None)
        environ["lab.tls_alpn"] = getattr(self.connection, "lab_alpn", [])
        environ["lab.tls_sni"] = getattr(self.connection, "lab_sni", None)
        environ["lab.tls_extensions"] = getattr(self.connection, "lab_extensions", [])
        return environ

    def log_request(self, code="-", size="-"):
        pass  # the app logs decisions; per-request access logs are noise here


class LabTLSServer(ThreadedWSGIServer):
    """Threaded Werkzeug server that fingerprints and terminates TLS itself."""

    def __init__(self, host, port, app, certfile, keyfile):
        super().__init__(host, port, app, handler=LabRequestHandler)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(certfile, keyfile)
        self.tls.set_alpn_protocols(["http/1.1"])

    def finish_request(self, request, client_address):
        # Runs in the per-connection worker thread, so a slow client
        # never blocks the accept loop.
        try:
            raw = peek_client_hello(request)
            hello = parse_client_hello(raw)
            fingerprint = ja4_from_bytes(raw)
            tls_sock = self.tls.wrap_socket(request, server_side=True)
        except (NotClientHello, ssl.SSLError, OSError):
            return  # not TLS, or the handshake failed (e.g. untrusted cert)
        tls_sock.lab_ja4 = fingerprint
        tls_sock.lab_alpn = hello["alpn"]
        tls_sock.lab_sni = hello["sni"]
        tls_sock.lab_extensions = hello["extensions"]
        tls_sock.settimeout(30)
        try:
            super().finish_request(tls_sock, client_address)
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                tls_sock.close()
            except OSError:
                pass


def serve(app, host, port, certfile, keyfile):
    server = LabTLSServer(host, port, app, certfile, keyfile)
    print(f" * Demo store on https://localhost:{port}  (TLS + JA4 at the edge)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
