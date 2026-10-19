"""
W2 Ch3 — start the TLS edge (fingerproxy) in front of the store, in the foreground.

    https://localhost:8443  ──▶  fingerproxy  ──▶  http://127.0.0.1:5000 (the store)

Equivalent to:
    bin/fingerproxy -listen-addr 127.0.0.1:8443 -forward-url http://127.0.0.1:5000 \\
        -cert-filename certs/tls.crt -certkey-filename certs/tls.key \\
        -metrics-listen-addr 127.0.0.1:9035

Everything binds to loopback. Prometheus metrics (handshake and fingerprinting durations) are on
http://127.0.0.1:9035/metrics. The edge does not care about DEFENSE_LEVEL: leave it running for the
whole session and only change the level (the checkpoint does, with POST /lab/level).

    python tools/edge.py                      # EDGE_PORT=8443, forwards to the port in DEMO_URL (5000)
    EDGE_PORT=8444 PORT=8099 python tools/edge.py   # when the store is not on 5000 (set DEMO_URL for the attacks too)

`python tools/checkpoint.py` starts its own private edge on a free port, so this one is for the
rounds you run by hand (attacks/*.py, your own browser, tools/clienthello_dump.py).
"""

import os
import signal
import subprocess
import sys

import tls_edge


def main():
    tls_edge.check_ready()
    listen = os.environ.get("EDGE_PORT", "8443")
    origin = os.environ.get("PORT") or tls_edge.origin_port()
    metrics = os.environ.get("EDGE_METRICS_PORT", "9035")
    print(f"Edge: https://localhost:{listen} -> http://127.0.0.1:{origin}  (Ctrl+C to stop)")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    proc = subprocess.Popen(tls_edge.command(listen, origin, metrics))
    try:
        sys.exit(proc.wait())
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:         # also when this script is killed: do not leave an orphan edge on the port
            proc.terminate()


if __name__ == "__main__":
    main()
