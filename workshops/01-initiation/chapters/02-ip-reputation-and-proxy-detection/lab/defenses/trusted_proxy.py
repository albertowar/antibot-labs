"""
Round 4: read the client IP from the right of X-Forwarded-For.

Wiring this check is the fix. While a check named `trusted_proxy` is enforced at the current
level, client_ip(ctx) (defenses/client_ip.py) stops trusting the leftmost entry and returns
the first hop your own proxies did not add: here, the address the edge saw. Every IP-based
check keys on client_ip(), so the rate limit, the blocklists and the reputation score all
start looking at the real address at once.

The check itself adds weak evidence, never a verdict on its own:

    xff_mismatch         10   the client sent an X-Forwarded-For that disagrees with the edge
    xff_internal_claim   20   ... and it claims to be an internal address (127.0.0.1, 10.x)

Weak, because honest clients send X-Forwarded-For too: a shopper behind a corporate proxy or
an old forward proxy arrives with a chain. Treat the left side as a hint, never as identity.

What it catches: forged chains, which Rounds 1-3 handed straight to every IP-based check.
What it misses: origin bypass. If an attacker can reach the origin without passing the edge,
they write the whole chain, including the "trusted" last entry. Lock the origin to the edge
(firewall on the CDN's ranges, mutual TLS, or a shared secret the edge adds). The lab's edge
is in-process, so there is no origin to reach around it; this stays a discussion question.
Who it hurts: nobody in the shopper population (none of them send X-Forwarded-For).
"""

from . import policy
from .client_ip import _valid_ip, forwarded_chain, is_internal
from .pipeline import Check, Signal


def _check(ctx):
    chain = forwarded_chain(ctx)
    if len(chain) < 2:
        return None
    claimed = _valid_ip(chain[0])
    if claimed == ctx.edge.ip:
        return None                    # the client told the truth
    if claimed is None:
        return [Signal("trusted_proxy", "xff_mismatch", policy.XFF_POINTS["xff_mismatch"], chain[0][:40])]
    name = "xff_internal_claim" if is_internal(claimed) else "xff_mismatch"
    return [Signal("trusted_proxy", name, policy.XFF_POINTS[name], claimed)]


CHECK = Check("trusted_proxy", _check)
