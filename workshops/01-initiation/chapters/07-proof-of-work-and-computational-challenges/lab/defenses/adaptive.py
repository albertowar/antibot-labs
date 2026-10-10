"""
Chapter 7 — Round 4 Defense (L4): adaptive (risk-based) difficulty

A fixed difficulty forces one compromise for everybody: too low and bots
barely notice, too high and phones suffer. Adaptive difficulty charges by
risk instead. Here the risk signal is the simplest one there is: how many
requests this client made in the last WINDOW_S seconds (a sliding window,
see spend_store.hit).

    rate <= 30/min   -> 16 bits   (~65k hashes, a browsing human)
    rate <= 120/min  -> 20 bits   (16x the work)
    rate  > 120/min  -> 22 bits   (64x the work)

Production systems do the same with richer signals:
  - Anubis adds "weight" per rule (UA, ASN, country, headers) and maps
    weight ranges to challenge difficulty.
  - Tor onion services publish a *suggested effort* that rises and falls
    with the queue of pending introductions (Proposal 327).

Trade-offs:
  - The key decides who shares a price. Keyed by IP, every household
    behind a carrier-grade NAT (CGNAT) shares one rate, and their phones
    pay the 22-bit price for each other's browsing. That is the false
    positive Round 4 measures.
  - The attacker controls the key. More IPs (residential proxies, see
    Chapter 3) and slower pacing put every identity back in the cheapest
    bucket. That is Round 4's attack.
"""

from __future__ import annotations

WINDOW_S = 60

# (max requests in the window, difficulty in bits); the last row catches the rest
LADDER = [(30, 16), (120, 20), (None, 22)]


def rate_key(client_ip: str) -> str:
    """Which requests share a rate counter.

    TODO (Round 4): try keying by the /24 instead of the IP
    (e.g. '.'.join(client_ip.split('.')[:3])). Re-run the checkpoint:
    what happens to round4_distributed, and to the CGNAT neighbour?
    """
    return f"pow:rate:{client_ip}"


def difficulty_for(rate: int) -> int:
    for limit, bits in LADDER:
        if limit is None or rate <= limit:
            return bits
    return LADDER[-1][1]


if __name__ == "__main__":
    for rate in (5, 30, 31, 120, 121, 500):
        print(f"  {rate:>4} req/min -> {difficulty_for(rate)} bits")
