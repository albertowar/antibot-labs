"""
W3 Ch3 — Shared helpers for the lab tools (path + localhost guard)

Importing this puts demo_site/, defenses/ and attacks/ on sys.path so a tool
can `import stream`, `import consumer`, or load an attack module, wherever it is
run from. ensure_local() is the rules-of-engagement guard for any tool that
would reach the network (only the optional --live paths do).
"""

import os
import sys
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # lab/
for _d in ("demo_site", "defenses", "attacks", "tools"):
    _p = os.path.join(ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def ensure_local(url):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        raise SystemExit(f"Refusing to run against {host!r}: lab tools only target this machine.")
    return url
