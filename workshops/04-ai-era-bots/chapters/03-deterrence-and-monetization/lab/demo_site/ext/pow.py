"""W4 Ch3 extension (Round 5): the `pow` challenge type, so that `challenge` is an answer a client can earn.

    hooks.challenges.register("pow", ...)   GET /api/challenge?type=pow, POST /api/challenge/verify,
                                            and the 403 interstitial the gate serves

Chapter 1's policy could answer a suspected crawler with `challenge` only by registering a placeholder
nobody could solve. This type is solvable: the interstitial (or, for /api/ paths, the JSON
`challenge_required`) carries a signed hashcash puzzle, a client POSTs the counter it found to
/api/challenge/verify, and the gate grants its session a clearance that lasts policy.POW_PASS_TTL
seconds. What the clearance is worth (a page budget, a binding to the address) is decided in
defenses/pow_gate.py, not here. Nothing is served at levels 0-4: no check there asks for a `pow`
challenge. There is no page script: a real deployment (Anubis) solves the puzzle in the visitor's
browser; here the solver is Python (tools/pow_client.py), which is what a crawler would use.
"""

import importlib

from .. import hooks


def _d(name):
    """A defense module, looked up at call time (the reloader reloads in place; a held reference would go stale)."""
    return importlib.import_module(f"defenses.{name}")


def init(app):
    hooks.challenges.register("pow", issue=lambda ctx: _d("pow_challenge").issue(ctx),
                              verify=lambda ctx, answer: _d("pow_challenge").verify(ctx, answer),
                              render="pow/interstitial.html", clearance_ttl=_d("policy").POW_PASS_TTL)
