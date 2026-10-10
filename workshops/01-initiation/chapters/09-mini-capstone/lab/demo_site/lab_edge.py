"""
W1 Ch9 — The lab edge: a pretend CDN in front of the store (W1 Ch3).

On a laptop every request comes from 127.0.0.1, which makes IP reputation,
rate limiting and shared IPs impossible to practise. Every lab actor
(tools/labnet.py) therefore says which source IP it "rents" from a pool in
data/world.json, and this middleware treats that address as the TCP peer.

Rules of the game, enforced here:
  1. Loopback only. The store refuses anything that isn't from this machine.
  2. X-Lab-Source-IP must come from a pool. Nobody can forge a TCP source
     address and still get the reply, so an attacker may rent a different
     IP, but may not invent one.
  3. Client-supplied X-Forwarded-For is dropped, as a trusted edge does
     (W1 Ch3: never take the client's word for its own address).
  4. X-Lab-Actor is the ground-truth label ("human:mobile_cgnat:03",
     "bot:wave2") the scoreboard uses. It is removed BEFORE the defenses
     run, so no layer can cheat by reading it.

A browser you open yourself sends no X-Lab-* headers: it gets the world's
`student_ip`, a home broadband address.
"""

import json

LOOPBACK = {"127.0.0.1", "::1"}


class LabEdge:
    def __init__(self, app, world_file):
        with open(world_file) as f:
            world = json.load(f)
        self.app = app
        self.allowed = {ip for pool in world["pools"].values() for ip in pool["ips"]}
        self.student_ip = world["student_ip"]

    def __call__(self, environ, start_response):
        if environ.get("REMOTE_ADDR") not in LOOPBACK:
            return self._refuse(start_response, "403 Forbidden", "The lab store only accepts loopback traffic.")
        source = environ.pop("HTTP_X_LAB_SOURCE_IP", None) or self.student_ip
        if source not in self.allowed:
            return self._refuse(start_response, "421 Misdirected Request",
                                f"{source} is not in any data/world.json pool. Rent an IP, don't invent one.")
        environ["lab.actor"] = environ.pop("HTTP_X_LAB_ACTOR", "you")
        environ.pop("HTTP_X_FORWARDED_FOR", None)
        environ["REMOTE_ADDR"] = source
        return self.app(environ, start_response)

    @staticmethod
    def _refuse(start_response, status, message):
        start_response(status, [("Content-Type", "text/plain; charset=utf-8")])
        return [message.encode()]
