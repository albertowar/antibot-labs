"""
Chapter 6 — Reset lab state: Redis (sessions, challenges, counters, solve
log) and the mock provider's tokens. Accounts and vouchers start from zero.

Run:
    python tools/reset.py
"""

import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import PROVIDER_URL, redis_client, require_local  # noqa: E402

if __name__ == "__main__":
    require_local()
    redis_client().flushdb()
    try:
        httpx.post(f"{PROVIDER_URL}/lab/reset", timeout=5)
    except httpx.HTTPError:
        pass
    print("Lab state cleared.")
