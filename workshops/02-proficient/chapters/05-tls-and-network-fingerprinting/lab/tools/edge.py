"""
Chapter 5 — Start the TLS edge (fingerproxy) in front of the demo site

    https://localhost:8443  ──▶  fingerproxy  ──▶  http://127.0.0.1:5000 (Flask)

Equivalent to:
    bin/fingerproxy -listen-addr 127.0.0.1:8443 -forward-url http://127.0.0.1:5000 \\
        -cert-filename certs/tls.crt -certkey-filename certs/tls.key \\
        -metrics-listen-addr 127.0.0.1:9035

Everything binds to loopback. Prometheus metrics (handshake and
fingerprinting durations) are on http://127.0.0.1:9035/metrics.

The edge doesn't care about DEFENSE_LEVEL; leave it running for the whole
lab and only restart Flask between rounds.

Run:
    python tools/edge.py              # EDGE_PORT=8443, PORT=5000 by default
"""

import os
import subprocess
import sys

from get_fingerproxy import LAB, binary_path


def main():
    binary = binary_path()
    cert = os.path.join(LAB, "certs", "tls.crt")
    if not os.path.exists(binary):
        sys.exit("fingerproxy not installed. Run: python tools/get_fingerproxy.py")
    if not os.path.exists(cert):
        sys.exit("No certificate yet. Run: python tools/make_cert.py")
    edge_port = os.environ.get("EDGE_PORT", "8443")
    origin_port = os.environ.get("PORT", "5000")
    cmd = [
        binary,
        "-listen-addr", f"127.0.0.1:{edge_port}",
        "-forward-url", f"http://127.0.0.1:{origin_port}",
        "-cert-filename", cert,
        "-certkey-filename", os.path.join(LAB, "certs", "tls.key"),
        "-metrics-listen-addr", "127.0.0.1:9035",
    ]
    print(f"Edge: https://localhost:{edge_port} → http://127.0.0.1:{origin_port}  (Ctrl+C to stop)")
    try:
        sys.exit(subprocess.call(cmd))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
