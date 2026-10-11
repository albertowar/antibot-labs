"""DNS for the gate: the lab fixture by default, the real resolver as a bonus.

Reverse DNS is the oldest crawler-verification method and the lab must run
offline and deterministically, so `MockResolver` asks the "mock internet"
(tools/mock_internet.py) for PTR and A records drawn from tools/fixtures/dns_zones.json.
The mock adds a realistic ~15 ms per query so the cost of an uncached lookup shows
up in the scoreboard, exactly as a real resolver round trip would.

`SystemResolver` uses dnspython against your real resolver. It exists for
tools/verify_real.py (checking an IP from *your own* logs) and is never used by
the rounds: a lab must not depend on, or generate traffic toward, third parties.

    LAB_DNS=mock    (default) ask the mock internet at MOCK_URL
    LAB_DNS=system  ask the operating system's resolver
"""

from __future__ import annotations

import os

import httpx

MOCK_URL = os.environ.get("MOCK_URL", "http://127.0.0.1:5001")
TIMEOUT_S = 2.0


class MockResolver:
    def __init__(self, base: str = MOCK_URL):
        self.base = base
        self.client = httpx.Client(base_url=base, timeout=TIMEOUT_S)

    def ptr(self, ip: str) -> list[str]:
        """Reverse lookup: the names the IP's owner has published for it."""
        try:
            return self.client.get("/dns/ptr", params={"ip": ip}).json().get("names", [])
        except httpx.HTTPError:
            return []

    def a(self, name: str) -> list[str]:
        """Forward lookup: the addresses the name's owner has published for it."""
        try:
            return self.client.get("/dns/a", params={"name": name}).json().get("addrs", [])
        except httpx.HTTPError:
            return []


class SystemResolver:
    def __init__(self):
        import dns.resolver  # dnspython, only needed on this path
        import dns.reversename
        self._dns = dns
        self.res = dns.resolver.Resolver()
        self.res.lifetime = TIMEOUT_S

    def ptr(self, ip: str) -> list[str]:
        try:
            rev = self._dns.reversename.from_address(ip)
            return [str(r.target).rstrip(".") for r in self.res.resolve(rev, "PTR")]
        except Exception:
            return []

    def a(self, name: str) -> list[str]:
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                out += [r.address for r in self.res.resolve(name, rtype)]
            except Exception:
                pass
        return out


def get_resolver():
    return SystemResolver() if os.environ.get("LAB_DNS", "mock") == "system" else MockResolver()
