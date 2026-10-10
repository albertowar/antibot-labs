"""
Chapter 5 — Round 0 tool: capture raw ClientHello bytes (no root, no tshark)

A tiny HTTPS server on https://localhost:9443 that *peeks* at the first TLS
record of each connection before handing the socket to Python's `ssl` module.
The peeked bytes are the client's ClientHello, exactly as sent on the wire.

For every connection it:
  1. saves the record as hex to captures/<label>.hex   (label = ?label=… in the URL)
  2. prints the parsed fields plus JA3 and JA4 (defenses/ja4.py)
  3. finishes the handshake and answers with a small JSON body, so the client
     doesn't error out.

Trade-off: this server only offers ALPN http/1.1, so h2-capable clients fall
back to HTTP/1.1 here. That doesn't change the ClientHello (the client
advertises h2 before it knows what the server supports), but it's why the
HTTP/2 fingerprint can only come from the real edge (fingerproxy on :8443).

Usage:
    python tools/clienthello_dump.py                     # terminal 1
    curl -sk "https://localhost:9443/?label=curl"         # terminal 2
    python attacks/round0_recon.py --dump                 # all lab clients at once
    python defenses/ja4.py captures/curl.hex              # then compute JA4 yourself
"""

import json
import os
import socket
import ssl
import sys
import threading
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "defenses"))

import ja4  # noqa: E402

PORT = int(os.environ.get("DUMP_PORT", "9443"))
CERT = os.path.join(LAB, "certs", "tls.crt")
KEY = os.path.join(LAB, "certs", "tls.key")
CAPTURES = os.path.join(LAB, "captures")


def peek_record(conn: socket.socket, timeout: float = 5.0) -> bytes:
    """Return the first full TLS record without consuming it from the socket."""
    conn.settimeout(timeout)
    want = 5
    data = b""
    while len(data) < want:
        data = conn.recv(65536, socket.MSG_PEEK)
        if not data:
            return b""
        if len(data) >= 5:
            want = 5 + int.from_bytes(data[3:5], "big")
        if len(data) < want:
            threading.Event().wait(0.01)
    return data[:want]


def handle(conn: socket.socket, addr, ctx: ssl.SSLContext) -> None:
    try:
        record = peek_record(conn)
        if not record:
            return
        ch = ja4.parse_client_hello(record)
        tls = ctx.wrap_socket(conn, server_side=True)
        request = tls.recv(65536).decode("latin-1")
        target = request.split(" ", 2)[1] if request.count(" ") >= 2 else "/"
        label = parse_qs(urlparse(target).query).get("label", [f"conn-{addr[1]}"])[0]
        label = "".join(c for c in label if c.isalnum() or c in "-_.")[:40] or "capture"
        os.makedirs(CAPTURES, exist_ok=True)
        path = os.path.join(CAPTURES, f"{label}.hex")
        with open(path, "w") as f:
            f.write(record.hex())
        print(f"\n=== {label}  ({len(record)} bytes → {os.path.relpath(path, LAB)}) ===")
        print(ja4.describe(ch))
        body = json.dumps({"label": label, "ja4": ja4.ja4(ch), "ja3": ja4.ja3(ch),
                           "bytes": len(record)}).encode()
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        tls.close()
    except (ssl.SSLError, ValueError, OSError) as exc:
        print(f"[{addr[0]}:{addr[1]}] {type(exc).__name__}: {exc}")
    finally:
        conn.close()


def main() -> None:
    if not os.path.exists(CERT):
        sys.exit("No certificate yet. Run: python tools/make_cert.py")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(16)
    print(f"ClientHello dump listening on https://localhost:{PORT}  (Ctrl+C to stop)")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, ctx), daemon=True).start()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
