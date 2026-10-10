"""
Chapter 6 — No-Docker fallback: an in-memory Redis server on 127.0.0.1
(port taken from REDIS_URL, default 6379)

fakeredis speaks the Redis protocol well enough for this lab (sessions,
GETDEL, INCR/EXPIRE, streams). Data disappears when you stop it. Use the
real Redis from docker-compose.yml if you can: it is what production runs.

Run (in its own terminal):
    python tools/fake_redis.py
"""

import os
import sys
from urllib.parse import urlparse

from fakeredis import TcpFakeServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import REDIS_URL  # noqa: E402

if __name__ == "__main__":
    address = ("127.0.0.1", urlparse(REDIS_URL).port or 6379)
    server = TcpFakeServer(address, server_type="redis")
    print(f"fakeredis listening on {address[0]}:{address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
