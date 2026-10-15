"""
Round checkpoint for W3 Ch1 (Mobile Apps, Attestation & MitM). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attacker next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attacker against Round 2's defense (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 over your files (.bak kept)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is WIRE-IT: Rounds 1-4 each ship one stub with a TODO (Round 1 is client code, Rounds 2-4 are checks
already wired into defenses/ladder.py), and solutions/round<N>/ holds the finished file. The provider mock
(defenses/mobile_core.py) is infrastructure, not a TODO.

    round  level  defense you write                          attacker                       gets through the stub?
    -----  -----  -----------------------------------------  -----------------------------  -----------------------
      1    1      certificate pinning (pinned_client.py)     intercept and replay           yes (the pin is checked separately)
      2    2      require a provider verdict                 no verdict / a forged one      yes, until the check exists
      3    3      bind it: hash, fresh, single-use nonce     a lifted genuine verdict       yes, until the check exists
      4    4      integrity + device/address velocity        an emulator farm               yes, until the check exists

A round passes when the attacker gets what the round expects AND no shopper is refused outright. Round 4
refuses the three GrapheneOS customers at checkout (the challenge band is enforced as a refusal because the
store has no step-up flow): the checkpoint lists them as the cost instead of failing, and fails if anyone else
is touched. Defender cost is the median gate time of the shoppers' buys (Server-Timing: gate).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch1  # noqa: E402,F401  (registers the ch1_mobile scenario)
import population  # noqa: E402
import labclient  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402

GATE_MEDIAN_MAX_MS = 25.0           # median gate time per shopper buy (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis every check costs a network round trip
FRICTION_PERSONA = "consumer_vpn"   # the three GrapheneOS customers


def pin_holds(board, results, attacks):
    held = bool((attacks.get("intercept") or {}).get("pin_refuses"))
    print(f"\ncertificate pinning (defenses/pinned_client.py)\n  an intercepted certificate is {'refused' if held else 'ACCEPTED'}")
    return held, "the pinned client accepted a proxy's certificate: implement check_pin"


def friction(expected):
    """The shoppers the gate answered with its challenge band: exactly `expected` personas, nobody else."""
    def check(board, results, attacks):
        got = sorted({r["persona"] for r in results if r.get("outcome") == "challenged"})
        n = sum(1 for r in results if r.get("outcome") == "challenged")
        bought = sum(1 for r in results if r.get("outcome") == "bought")
        print(f"\nthe people: {len(results)} shoppers · bought {bought} · challenged {n}" + (f" ({', '.join(got)})" if got else ""))
        want = sorted(expected)
        return got == want, f"challenged personas {got}, expected {want}"
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:", "path": "/api/mobile/buy"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return False, "no shopper buys in the decision log"
    redis_url = labclient.admin("GET", "/lab/config")["redis_url"]
    limit = GATE_MEDIAN_MAX_MS if redis_url.startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    median = statistics.median(ms)
    print(f"\ndefender cost (the shoppers' buys)\n  gate per buy: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} buys")
    return median < limit, f"gate median {median:.2f} ms > {limit} ms"


def make_round(level, description, attack, name, expect, checks=(), **kw):
    return Round(level=level, description=description, scenario="ch1_mobile", attacks={name: attack}, expect={name: expect},
                 extra_checks=[*checks, gate_cost], **kw)


ROUNDS = {
    1: make_round(1, "pin the certificate: the proxy can no longer read the app", "attacks/round1_intercept.py", "intercept", "full",
                  [pin_holds, friction([])], solutions=("defenses/pinned_client.py",)),
    2: make_round(2, "require a provider verdict: no verdict, no pair", "attacks/round2_unpin.py", "unpin", "blocked",
                  [friction([])], solutions=("defenses/attestation.py",)),
    3: make_round(3, "bind it to the request: hash, freshness, single-use nonce", "attacks/round3_replay.py", "replay", "blocked",
                  [friction([])], solutions=("defenses/request_signing.py",)),
    4: make_round(4, "score the device: integrity and velocity stop the farm", "attacks/round4_farm.py", "farm", "blocked",
                  [friction([FRICTION_PERSONA])], solutions=("defenses/device_verdict.py",)),
}

if __name__ == "__main__":
    main(ROUNDS)
