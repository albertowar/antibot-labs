"""
The TLS edge as a side service: start fingerproxy in front of the store, find it again.

    client --TLS--> fingerproxy :<port> --HTTP + X-JA4-Fingerprint, X-HTTP2-Fingerprint--> the store

Two entry points:
  - `python tools/edge.py` runs it in the foreground for you (https://localhost:8443).
  - `ensure()` starts a private one on a free port for the checkpoint and the verify harness,
    exports its URL as TLS_EDGE_URL for the attack scripts, and stops it at exit. A checkpoint
    therefore never collides with the edge you left running in another terminal, or with another
    checkout's. Set TLS_EDGE_URL yourself (to an edge you started) to make `ensure()` use that one.

Everything binds to loopback, and every URL goes through labnet (a TLS edge on another host would
make the lab's traffic leave this machine).
"""

import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402,F401  (puts the lab root on sys.path and runs the labnet guard)
import labnet  # noqa: E402
from get_fingerproxy import LAB, binary_path  # noqa: E402

DEFAULT_URL = "https://localhost:8443"
CERT = os.path.join(LAB, "certs", "tls.crt")
KEY = os.path.join(LAB, "certs", "tls.key")
_running = {}


def edge_url():
    """Where the attacks send their traffic: TLS_EDGE_URL, default https://localhost:8443 (guarded: local only)."""
    return labnet.target("TLS_EDGE_URL", DEFAULT_URL)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check_ready():
    """Exit with the setup hint when the binary is missing; create the self-signed certificate if it is."""
    if not os.path.exists(binary_path()):
        sys.exit("fingerproxy is not installed. Run once: python tools/get_fingerproxy.py")
    if not os.path.exists(CERT):
        import make_cert            # local and free: a self-signed certificate for https://localhost
        make_cert.main()


def command(listen_port, origin_port, metrics_port):
    return [binary_path(), "-listen-addr", f"127.0.0.1:{listen_port}", "-forward-url", f"http://127.0.0.1:{origin_port}",
            "-cert-filename", CERT, "-certkey-filename", KEY, "-metrics-listen-addr", f"127.0.0.1:{metrics_port}"]


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def origin_port():
    """The store's port, from DEMO_URL (what labclient resolved)."""
    return labclient.BASE_URL.rsplit(":", 1)[-1].rstrip("/")


def ensure():
    """Make sure an edge in front of the store is reachable; returns its URL (and exports TLS_EDGE_URL)."""
    if os.environ.get("TLS_EDGE_URL"):
        return edge_url()
    if "url" in _running:
        return _running["url"]
    check_ready()
    listen, metrics = free_port(), free_port()
    proc = subprocess.Popen(command(listen, origin_port(), metrics), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(listen):
        proc.kill()
        sys.exit("The TLS edge (fingerproxy) did not start. Run python tools/edge.py to see why.")
    _running.update(proc=proc, url=f"https://localhost:{listen}")
    os.environ["TLS_EDGE_URL"] = _running["url"]
    import atexit
    atexit.register(stop)
    return _running["url"]


def stop():
    proc = _running.pop("proc", None)
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if _running.pop("url", None) is not None:
        os.environ.pop("TLS_EDGE_URL", None)
