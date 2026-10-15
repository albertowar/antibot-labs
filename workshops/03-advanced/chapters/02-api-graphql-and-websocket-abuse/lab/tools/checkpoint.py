"""
Round checkpoint for W3 Ch2 (API, GraphQL & WebSocket Abuse). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attackers next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attackers against Round 2's defense (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 over your files (.bak kept)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is WIRE-IT: every round ships one stub with a TODO and the finished file is in solutions/round<N>/. The
checks are already wired into defenses/ladder.py; the stubs return nothing until you write the TODO.

    round  level  defense you write                       attacker                              gets through the stub?
    -----  -----  --------------------------------------  ------------------------------------  ----------------------
      1    1      cost-aware rate limit (rate_cost)       bulk export + id walk                 yes
      2    2      query limits (graphql_limits)           introspection, alias batch            yes
      3    3      trusted documents (persisted_queries)   alias amplification via a fragment    yes (and through Round 2's)
      4    4      connection guard (ws_guard)             CSWSH, anonymous bids, authed flood   yes
      5    5      request signing (request_signing)       token replay, naive and spoofed       the spoofed one (binding
                                                                                                 stops the naive one)

A round passes when every attacker is held to what the round expects AND no shopper is refused. The 40 shoppers
use the store through its three surfaces (tools/personas_ch2.py): REST and persisted GraphQL, the signed mobile
app, the live feed. Defender cost is the median gate time over their requests (Server-Timing: gate; a WebSocket
connection logs the cost of an average frame).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch2  # noqa: E402,F401  (registers the ch2_api scenario)
import labclient  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402

GATE_MEDIAN_MAX_MS = 25.0           # median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis every check costs a network round trip


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows if not d["path"].startswith("/lab")]
    if not ms:
        return False, "no shopper requests in the decision log"
    redis_url = labclient.admin("GET", "/lab/config")["redis_url"]
    limit = GATE_MEDIAN_MAX_MS if redis_url.startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    median = statistics.median(ms)
    print(f"\ndefender cost (the shoppers' requests)\n  gate per request: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} requests")
    return median < limit, f"gate median {median:.2f} ms > {limit} ms"


def the_people(board, results, attacks):
    roles = {}
    for r in results:
        row = roles.setdefault(r.get("role", "?"), [0, 0])
        row[0] += 1
        row[1] += r.get("outcome") == "browsed"
    print("\nthe people: " + " · ".join(f"{role} {ok}/{n} finished" for role, (n, ok) in sorted(roles.items())))
    return True, ""


def poisoned(board, results, attacks):
    """Round 5: whoever the signature stopped must have been *deceived*, not refused, on the inventory read."""
    bad = [n for n, out in attacks.items() if not out.get("poisoned")]
    print("\nresponse deception (defenses/response_deception.py)\n  " +
          "; ".join(f"{n}: price {out.get('inventory_price')} (real {out.get('real_price')})" for n, out in attacks.items()))
    return not bad, f"the inventory read was not poisoned for {bad}"


def make_round(level, description, attacks, solution, checks=(), **kw):
    names = {k: v for k, v in attacks.items()}
    return Round(level=level, description=description, scenario="ch2_api", attacks=names,
                 expect={k: "blocked" for k in names}, extra_checks=[the_people, *checks, gate_cost],
                 solutions=(f"defenses/{solution}.py",), **kw)


ROUNDS = {
    1: make_round(1, "cost-aware rate limiting: the bulk export and the id walk stop",
                  {"scrape": "attacks/round1_scrape.py"}, "rate_cost"),
    2: make_round(2, "query limits: no introspection, no alias batch",
                  {"introspection": "attacks/round2_graphql_batch.py --only introspection",
                   "alias_batch": "attacks/round2_graphql_batch.py --only alias_batch"}, "graphql_limits"),
    3: make_round(3, "trusted documents: the fragment amplification is not on the list",
                  {"fragment_amp": "attacks/round3_fragment_amp.py"}, "persisted_queries"),
    4: make_round(4, "connection guard: Origin, auth for bids, a message budget per connection",
                  {"cswsh": "attacks/round4_ws_flood.py", "anon": "attacks/round4_ws_flood.py --origin-ok",
                   "authed": "attacks/round4_ws_flood.py --login"}, "ws_guard"),
    5: make_round(5, "request signing: the stolen token is not enough, and the bot is fed poison",
                  {"replay": "attacks/round5_token_replay.py", "replay_spoofed": "attacks/round5_token_replay.py --spoof"},
                  "request_signing", [poisoned]),
}

if __name__ == "__main__":
    main(ROUNDS)
