"""
Round 5 (level 5, support module) - bearer-token binding.

A complement to request signing: embed a coarse fingerprint of the client in the token at issue time and check it
on use. The claim is deliberately *coarse* - the class of network the request comes from (a hosting provider or
an ordinary eyeball network, from the ASN feed in data/feeds/hosting_asns.csv) and the User-Agent family - so
that a legitimate client changing address within the same class (a laptop moving between office NAT addresses)
still matches, while a token issued to a residential app and replayed from a datacenter scraper does not.

This ships complete; it is not the Round 5 exercise. It exists to show that signing and binding are layers, not
substitutes: binding catches a naive replay even when the attacker omits signing entirely, and signing catches a
replay even when the attacker spoofs the coarse client signals (rents an eyeball address and copies the
User-Agent: that attacker passes binding and only signing stops them).

False positives: bind only on signals stable across a session. The address itself is too volatile (mobile
hand-off, CGNAT reassignment); the network class and the UA family are coarse enough to tolerate normal drift.
Even so, a phone that moves from Wi-Fi to a hosting-ASN VPN mid-session fails the check: allow a re-bind on a
fresh authenticated login rather than hard-failing forever.
"""

import csv
import hashlib
import os

from .pipeline import Check, Signal

BLOCK_POINTS = 80          # policy blocks at >= 75
FEED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds", "hosting_asns.csv")
_hosting = None


def _hosting_asns():
    global _hosting
    if _hosting is None:
        with open(FEED, newline="") as fh:
            _hosting = {int(row["asn"]) for row in csv.DictReader(fh)}
    return _hosting


def net_class(edge):
    return "hosting" if edge.asn in _hosting_asns() else "eyeball"


def binding_hash(ctx):
    """The claim a token is issued with: network class and UA family of the request that logged in."""
    return hashlib.sha256(f"{net_class(ctx.edge)}|{ctx.ua.family}".encode()).hexdigest()[:16]


def _check(ctx):
    bearer = ctx.attrs.get("bearer")
    if not bearer or not bearer.get("bind"):
        return None                                  # anonymous, or a token issued without a claim
    if binding_hash(ctx) != bearer["bind"]:
        return [Signal("token_binding", "client_changed", BLOCK_POINTS,
                       f"token used from a different client ({net_class(ctx.edge)}, {ctx.ua.family}) than it was issued to")]
    return None


CHECK = Check("token_binding", _check, phases=("action:api2_*",))
