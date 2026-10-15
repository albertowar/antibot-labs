"""DNS for the gate: the lab's mock internet, deterministic and offline.

Reverse DNS is the oldest crawler-verification method and the lab must run offline and
repeatably, so `MockResolver` asks the "mock internet" (tools/mock_internet.py, a side
service on 127.0.0.1) for PTR and A records drawn from tools/fixtures/dns_zones.json. The
mock adds a realistic ~15 ms per query so the cost of an uncached lookup shows up in the
scoreboard, exactly as a real resolver round trip would.

The service's URL is `MOCK_URL`. It is a side service, not the store, so it goes through the
`labnet` guard on every use (`labnet.target` refuses a MOCK_URL that is not this machine).
It is read when a resolver is built, not at import: the store may start the mock on a free
port after this module is imported.

A resolver against your real DNS exists only in tools/verify_real.py, the optional bonus that
checks an address from your own logs. The rounds never use it: a lab must not depend on, or
generate traffic toward, third parties.
"""

from __future__ import annotations

import httpx
import labnet

TIMEOUT_S = 2.0
_cache: dict = {}


class MockResolver:
    def __init__(self, base: str):
        self.base = base
        self.client = httpx.Client(base_url=base, timeout=TIMEOUT_S)

    def ptr(self, ip: str) -> list[str]:
        """Reverse lookup: the names the IP's owner has published for it."""
        try:
            return self.client.get("/dns/ptr", params={"ip": ip}).json().get("names", [])
        except (httpx.HTTPError, ValueError):
            return []

    def a(self, name: str) -> list[str]:
        """Forward lookup: the addresses the name's owner has published for it."""
        try:
            return self.client.get("/dns/a", params={"name": name}).json().get("addrs", [])
        except (httpx.HTTPError, ValueError):
            return []


def get_resolver() -> MockResolver:
    base = labnet.target("MOCK_URL", "http://127.0.0.1:5001")
    if _cache.get("base") != base:
        _cache.update(base=base, resolver=MockResolver(base))
    return _cache["resolver"]
