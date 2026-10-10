"""L5 — bearer-token binding (Round 5, support module).

A complement to request signing: embed a coarse fingerprint of the client in the
token at issue time and check it on use. The claim is deliberately *coarse* —
the egress network class and the User-Agent family — so that a legitimate client
changing IP within the same class (a laptop moving between office NAT addresses)
still matches, while a token issued to a residential browser and replayed from a
datacenter scraper does not.

This ships complete; it is not the Round 5 exercise. It exists to show that
signing and binding are layers, not substitutes: binding catches a replay even
when the attacker omits signing entirely, and signing catches a replay even when
the attacker spoofs the coarse client signals.

False positives: bind only on signals stable across a session. IP *address* is
too volatile (mobile hand-off, CGNAT reassignment); IP *class* and UA *family*
are coarse enough to tolerate normal drift. Even so, allow a re-bind on a fresh
authenticated login rather than hard-failing forever.
"""

from __future__ import annotations

import hashlib

BLOCK_POINTS = 60


def binding_hash(ip_class: str, ua_family: str) -> str:
    return hashlib.sha256(f"{ip_class}|{ua_family}".encode()).hexdigest()[:16]


def score(token_binding_claim: str | None, ip_class: str, ua_family: str) -> tuple[int, list[str]]:
    if not token_binding_claim:
        return 0, []  # no binding claim (e.g. anonymous or pre-L5 token)
    current = binding_hash(ip_class, ua_family)
    if current != token_binding_claim:
        return BLOCK_POINTS, ["bearer token used from a different client than it was issued to"]
    return 0, []
