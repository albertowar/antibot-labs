"""The lab edge: a pretend CDN in front of the store (pattern from W1 Ch8).

On a laptop every request comes from 127.0.0.1, which makes source-address
reasoning impossible to practise. Every lab client therefore says which address
it "rents" with ``X-Lab-Source-IP``, and this middleware makes that address the
TCP peer the application sees.

Rules enforced here, so no defense can be fooled by a header:
  1. Loopback only. Anything that is not from this machine is refused.
  2. The address must exist in data/world.json. A client may rent a different
     address, but may not invent one (nobody forges a TCP source and still gets
     the reply).
  3. Client-supplied X-Forwarded-For is dropped, as a trusted edge does.
  4. ``X-Lab-Actor`` is ground truth for the scoreboard only. It is moved into
     the WSGI environ BEFORE the app runs, so no defense can read it.

A browser you open yourself sends no X-Lab-* headers: it gets the world's
``student_ip``, a home-broadband address.
"""

from __future__ import annotations

LOOPBACK = {"127.0.0.1", "::1"}


class LabEdge:
    def __init__(self, app, allowed_ips, student_ip):
        self.app = app
        self.allowed = set(allowed_ips)
        self.student_ip = student_ip

    def __call__(self, environ, start_response):
        if environ.get("REMOTE_ADDR") not in LOOPBACK:
            return self._refuse(start_response, "403 Forbidden",
                                "The lab store only accepts loopback traffic.")
        source = environ.pop("HTTP_X_LAB_SOURCE_IP", None) or self.student_ip
        if source not in self.allowed:
            return self._refuse(start_response, "421 Misdirected Request",
                                f"{source} is not in any data/world.json pool. Rent an address, don't invent one.")
        environ["lab.actor"] = environ.pop("HTTP_X_LAB_ACTOR", "you")
        environ.pop("HTTP_X_FORWARDED_FOR", None)
        environ["REMOTE_ADDR"] = source
        return self.app(environ, start_response)

    @staticmethod
    def _refuse(start_response, status, message):
        start_response(status, [("Content-Type", "text/plain; charset=utf-8")])
        return [message.encode()]
