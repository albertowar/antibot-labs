"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N. Level 0 is
Round 0: first come, first served behind Chapter 4's funnel (finished, shared with that lab). From level 1 the
store raffles the drop (demo_site/ext/raffle.py), and the ladder decides who may enter, what an entry weighs,
who is the same person, and what happens at the claim. Change this file, save, and the store picks it up on the
next request (LAB_RELOAD=1). Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the
reference version of every check up to round N, and of this file.

Each round's check is a stub you finish first (the `TODO (Round N)` in defenses/<check>.py); wiring it here is
the second half. Several of them run in batch phases ("raffle:draw", "raffle:rescore") over the whole entry list.
"""

from . import scalping_funnel

# from . import raffle_basics          # 1. import the round's check module

LADDER = {
    0: [scalping_funnel.CHECK],
    # TODO (Round 1): 1: [raffle_basics.CHECK]        - guests out, one entry per account, uniform tickets.
    # TODO (Round 2): 2: [eligibility.CHECK]          - verified email at entry, trust weights at the draw.
    # TODO (Round 3): 3: [entity_resolution.CHECK]    - normalize, link, one entry per cluster.
    # TODO (Round 4): 4: [weak_link_graph.CHECK]      - evidence graph, claim step-up and holds, re-score.
}
