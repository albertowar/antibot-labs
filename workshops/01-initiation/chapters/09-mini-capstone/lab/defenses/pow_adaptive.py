"""
Chapter 7, Round 4 defense (L4): adaptive (risk-based) difficulty.

A fixed difficulty forces one compromise for everybody: too low and bots barely notice,
too high and phones suffer. Adaptive difficulty charges by risk. Here the risk signal is
the simplest one there is: how many requests this client made in the last
policy.POW_RATE_WINDOW_S seconds.

    rate <= 10/min  -> 16 bits   (~65k hashes, a browsing human)
    rate <= 20/min  -> 20 bits   (16x the work)
    rate  > 20/min  -> 22 bits   (64x the work)

(policy.POW_ADAPTIVE holds the numbers.) The check counts the request, then leaves the
price in ctx.attrs["pow_bits"]; pow_challenge.issue() reads it when the challenge is
issued later in the same request.

Production systems do the same with richer signals: Anubis adds "weight" per rule (UA,
ASN, country, headers) and maps weight ranges to difficulty; Tor onion services publish
a suggested effort that rises with the queue of pending introductions (Proposal 327).

Trade-offs:
  - The key decides who shares a price. Keyed by IP, every household behind a
    carrier-grade NAT (CGNAT) shares one rate, and their phones pay the 22-bit price
    for each other's browsing. That is the false positive Round 4 measures.
  - The attacker controls the key. More IPs (residential proxies, Chapter 3) and
    slower pacing put every identity back in the cheapest bucket. That is Round 4's attack.
"""

from . import policy
from .pipeline import Check
from .store import Counters


def rate_key(ip):
    """Which requests share a rate counter.

    Exercise (Round 4, discussion): try keying by the /24 instead of the IP, with
    `from defenses.store import prefix_of` and `return prefix_of(ip)`.
    Re-run the checkpoint: what happens to round4_distributed, and to the shoppers?
    The model answer is in the README's Round 4 section. The checkpoint FAILs on purpose
    (it expects the IP key), and --catch-up does not undo the edit: put `return ip`
    back before Round 5.
    """
    return ip


def difficulty_for(rate):
    for limit, bits in policy.POW_ADAPTIVE:
        if limit is None or rate <= limit:
            return bits
    return policy.POW_ADAPTIVE[-1][1]


def _check(ctx):
    rate = Counters(ctx.redis, "lab:pow").hit("rate", rate_key(ctx.ip), policy.POW_RATE_WINDOW_S)
    ctx.attrs["pow_bits"] = difficulty_for(rate)
    ctx.note(pow_rate=rate, pow_bits=ctx.attrs["pow_bits"])


CHECK = Check("pow_adaptive", _check, phases=("request",))


if __name__ == "__main__":
    for rate in (5, 10, 11, 20, 21, 500):
        print(f"  {rate:>4} req/min -> {difficulty_for(rate)} bits")
