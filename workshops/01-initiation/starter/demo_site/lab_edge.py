"""
The lab edge: a pretend CDN in front of the store.

On a laptop every request comes from 127.0.0.1, which makes IP reputation,
rate limiting and shared addresses impossible to practise. Every lab actor
(tools/labclient.py) therefore says which source IP it "rents" from a pool in
data/world.json, and this middleware treats that address as the TCP peer.

Rules, enforced here:
  1. Loopback only. The store refuses anything that is not from this machine.
  2. X-Lab-Client-IP must fall inside a world.json pool. Nobody can forge a
     TCP source address and still get the reply, so an attacker may rent a
     different address, but may not invent one. Anything else is a 421.
  3. Client-supplied X-Forwarded-For never reaches the headers and the edge
     never trusts it. Like a CDN, it appends the peer and passes the chain on
     aside, as environ["lab.xff_claimed"] ("<what the client wrote>, <peer>"),
     so W1 Ch2 can show what goes wrong when an app reads the left of it.
  4. X-Lab-Actor is ground truth ("human:home:03", "bot:wave2") for the
     scoreboard. It is removed BEFORE the defenses run, so no check can read it.
  5. Every other X-Lab-* request header is removed too. X-Lab-JA4 is kept
     aside as a *claimed* TLS fingerprint until a TLS edge (W2 Ch5) measures
     a real one.

A browser you open yourself sends no X-Lab-* headers: it gets the world's
`student_ip`, a home broadband address.
"""

import ipaddress
import json

LOOPBACK = {"127.0.0.1", "::1"}


class World:
    def __init__(self, path):
        with open(path) as f:
            self.raw = json.load(f)
        self.student_ip = self.raw["student_ip"]
        self.pools = []
        for name, p in self.raw["pools"].items():
            if "cidr" in p:
                self.pools.append((ipaddress.ip_network(p["cidr"]), name, p))
            else:
                for ip in p.get("ips", []):
                    self.pools.append((ipaddress.ip_network(ip), name, p))
        self.blocklist = [ipaddress.ip_network(c) for c in self.raw.get("community_blocklist", [])]

    def resolve(self, ip):
        """What an ASN/geo database would say about an address. Pool `type` is NOT returned."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, name, p in self.pools:
            if addr.version == net.version and addr in net:
                return {"ip": str(addr), "asn": p["asn"], "org": p["org"], "country": p["country"], "pool": name}
        return None

    def pool_type(self, name):
        """Ground truth, for the scoreboard and tools only."""
        return self.raw["pools"].get(name, {}).get("type", "unknown")


class LabEdge:
    def __init__(self, app, world: World):
        self.app, self.world = app, world

    def __call__(self, environ, start_response):
        if environ.get("REMOTE_ADDR") not in LOOPBACK:
            return self._refuse(start_response, "403 Forbidden", "The lab store only accepts loopback traffic.")
        claimed = environ.pop("HTTP_X_LAB_CLIENT_IP", None) or self.world.student_ip
        info = self.world.resolve(claimed)
        if info is None:
            return self._refuse(start_response, "421 Misdirected Request",
                                f"{claimed} is not inside any data/world.json pool. Rent an address, don't invent one.")
        environ["lab.actor"] = environ.pop("HTTP_X_LAB_ACTOR", None) or "you"
        environ["lab.edge"] = info
        environ["lab.ja4_claimed"] = environ.pop("HTTP_X_LAB_JA4", "")
        client_xff = environ.pop("HTTP_X_FORWARDED_FOR", "")[:512].strip()
        environ["lab.xff_claimed"] = f"{client_xff}, {info['ip']}" if client_xff else info["ip"]
        for k in [k for k in environ if k.startswith("HTTP_X_LAB_")]:
            environ.pop(k)
        environ["REMOTE_ADDR"] = info["ip"]
        return self.app(environ, start_response)

    @staticmethod
    def _refuse(start_response, status, message):
        start_response(status, [("Content-Type", "text/plain; charset=utf-8")])
        return [message.encode()]
