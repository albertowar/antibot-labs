"""
Round checkpoint for W4 Ch2 (Verified Bot Identity). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's impostors next to the cohort
    python tools/checkpoint.py --round 3 --level 2    # the same impostors against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N. The store gives verified crawlers a fast lane (600 requests a
minute per identity) and everyone else the anonymous lane (30 a minute per address). Each round runs
the impostor that beats the PREVIOUS round's defense, plus the earlier ones to prove they stay out:

    round  defense added                              impostors run                         what you should see
    -----  -----------------------------------------  ------------------------------------  ---------------------------
      1    reverse DNS (PTR suffix)                    UA spoof                              held; 5 real crawlers throttled
      2    forward-confirmed rDNS + verdict cache      + forged PTR                          held; same 5 throttled
      3    published ranges + entitlement scoping      + GAE squat, GPTBot claim             held; only the signed agent throttled
      4    Web Bot Auth verification                   + self-signed agent                   agent admitted; the self-signed agent
                                                                                             takes the fast lane (the lesson)
      5    trust policy, window cap, nonce             + stale and fresh replay              self-signed held; stale 0, fresh 1

Next to the impostors run the starter's 40 shoppers and eight genuine crawlers
(tools/personas_ch2.py). A "limited" crawler is a false positive you chose: it is a real operator
your level cannot yet verify, and the cost is listed per level. "Held" means the impostor got
nothing from the verified lane and no more than the anonymous budget (30 plus the trickle that
refills while it runs). Defender cost: the gate time of every request that claimed an identity,
from the decision log, and what the mock internet was asked.
"""

import os
import statistics

import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch2  # noqa: E402  (the chapter's cohort, passed as Round.people, and the `lane_mix` scenario)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402
from personas_ch2 import CRAWL_PAGES  # noqa: E402

ATTACKS = {
    "spoof": "attacks/round1_ua_spoof.py",
    "ptr": "attacks/round2_ptr_spoof.py",
    "squat": "attacks/round3_range_squat.py",
    "self_signed": "attacks/round4_self_signed_agent.py",
    "stale": "attacks/round4_replay.py --stale",
    "fresh": "attacks/round4_replay.py --fresh",
}
ANON_PAGES_MAX = 45          # the anonymous budget: 30 up front plus the trickle (0.5/s) refilled while the attack runs
CLAIMANT_P50_MAX_MS = 100.0  # defender cost: median gate time of a request that claims an identity (L1 pays DNS, 15 ms a query)
SHOPPER_P50_MAX_MS = 25.0    # the shoppers' own gate time (in-process Redis); the gate ignores browsers
SHOPPER_P50_MAX_MS_REDIS = 250.0

# Genuine crawlers a level cannot verify yet: the false positives of that level, in the order of the rounds.
NO_RDNS = {"gptbot", "gptbot-new", "claudebot", "perplexitybot", "chatgpt-agent"}
THROTTLED = {0: set(), 1: NO_RDNS, 2: NO_RDNS, 3: {"chatgpt-agent"}, 4: set(), 5: set()}


def held(*names, nested=()):
    """Impostors named here got nothing from the verified lane and no more than the anonymous budget."""
    def check(board, results, attacks):
        print("\nimpostors                 pages taken   verified lane   429   403")
        bad = []
        for name in names:
            out = attacks.get(name) or {}
            for label, o in [(name, out)] + [(f"{name}/{k}", out[k]) for k in nested if k in out]:
                print(f"  {label:<22}{o.get('succeeded', '?'):>6} /{o.get('attempted', '?'):<5}{o.get('fast_lane', '?'):>9}"
                      f"{o.get('status_429', '?'):>14}{o.get('status_403', '?'):>6}")
                if o.get("fast_lane", 1) > (1 if name == "fresh" else 0) or o.get("succeeded", 999) > ANON_PAGES_MAX:
                    bad.append(f"{label}: took {o.get('succeeded')} pages, {o.get('fast_lane')} in the verified lane (held means <= {ANON_PAGES_MAX} and none in the fast lane)")
        return (not bad, "; ".join(bad))
    return check


def fast(*names):
    """Impostors that DO take the fast lane at this level: the lesson of the round, printed beside the table."""
    def check(board, results, attacks):
        for name in names:
            out = attacks.get(name) or {}
            print(f"  {name:<22}{out.get('succeeded', '?'):>6} /{out.get('attempted', '?'):<5}{out.get('fast_lane', '?'):>9} in the verified lane   (expected: it works at this level)")
        return (True, "")
    return check


def cohort(level):
    """The genuine crawlers: all 60 pages or throttled, against the set this level cannot verify."""
    def check(board, results, attacks):
        rows = {r["persona"]: r for r in results if r["actor"].startswith("legit:")}
        want = THROTTLED[level]
        print(f"\ngenuine crawlers (admitted = {CRAWL_PAGES}/{CRAWL_PAGES} pages)   served  limited  refused")
        bad = []
        for name, r in rows.items():
            admitted = r.get("served", 0) == CRAWL_PAGES
            mark = "ok" if admitted else "THROTTLED"
            print(f"  {name:<30}{mark:>10}{r.get('served', 0):>9}{r.get('limited', 0):>9}{r.get('blocked', 0):>9}")
            if r.get("blocked"):
                bad.append(f"{name} was refused (403): a genuine crawler must never be refused")
            elif admitted and name in want:
                bad.append(f"{name} was admitted but this level cannot verify it (a check that is too lax?)")
            elif not admitted and name not in want:
                bad.append(f"{name} was throttled at level {level}: a false positive this level should not have")
        print(f"  admitted {sum(1 for r in rows.values() if r.get('served', 0) == CRAWL_PAGES)}/{len(rows)}"
              f"   (expected throttled at level {level}: {', '.join(sorted(want)) or 'none'})")
        return (not bad, "; ".join(bad))
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000})["items"]
    claimants = sorted(d["ms"] for d in rows if d["actor"].startswith("legit:"))
    shoppers = [d["ms"] for d in rows if d["actor"].startswith("human:")]
    if not claimants or not shoppers:
        return (False, "no claimant or shopper requests in the decision log")
    p50 = statistics.median(claimants)
    p95 = claimants[int(len(claimants) * 0.95)]
    sp50 = statistics.median(shoppers)
    limit = SHOPPER_P50_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else SHOPPER_P50_MAX_MS_REDIS
    mock = requests.get(f"{_mock()}/stats", timeout=5).json()
    print(f"\ndefender cost (gate time per request, from the decision log)\n  crawlers: median {p50:.2f} ms, p95 {p95:.2f} ms over {len(claimants)} requests"
          f"   shoppers: median {sp50:.2f} ms\n  mock internet was asked: {mock['ptr']} PTR + {mock['a']} A lookups, {mock['ranges']} range fetches, {mock['dir']} directory fetches")
    bad = []
    if p50 > CLAIMANT_P50_MAX_MS:
        bad.append(f"crawler gate median {p50:.1f} ms > {CLAIMANT_P50_MAX_MS} ms")
    if sp50 > limit:
        bad.append(f"shopper gate median {sp50:.1f} ms > {limit} ms")
    return (not bad, "; ".join(bad))


def _mock():
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))
    from _common import mock_url
    return mock_url()


def share(prefix_names):
    """Metric: the share of the impostors' requests that were served from the verified lane."""
    def metric(board, results, attacks):
        outs = [attacks[n] for n in prefix_names if attacks.get(n)]
        total = sum(o["attempted"] for o in outs)
        return sum(o.get("fast_lane", 0) for o in outs) / total if total else 0.0
    return metric


def rnd(level, description, attacks, expect, solutions, extra, cap):
    return Round(level=level, description=description, scenario="lane_mix", people=personas_ch2.personas,
                legit_hurt_max=len(THROTTLED[level]),
                 attacks={n: ATTACKS[n] for n in attacks}, expect=expect, solutions=solutions,
                 metric=share(attacks), bot_success_max=cap, extra_checks=[*extra, cohort(level), gate_cost])


ROUNDS = {
    1: rnd(1, "L1 reverse DNS: the PTR must be under the operator's suffix", ["spoof"],
           {"spoof": "partial"}, ("defenses/rdns.py",), [held("spoof", nested=("honest",))], 0.0),
    2: rnd(2, "L2 forward-confirmed reverse DNS + verdict cache", ["spoof", "ptr"],
           {"spoof": "partial", "ptr": "partial"}, ("defenses/rdns.py",),
           [held("spoof", "ptr", nested=("substring",))], 0.0),
    3: rnd(3, "L3 published ranges + entitlement scoping", ["ptr", "squat"],
           {"ptr": "partial", "squat": "partial"}, ("defenses/ip_ranges.py",),
           [held("ptr", "squat", nested=("gptbot_claim",))], 0.0),
    4: rnd(4, "L4 Web Bot Auth verification (naive policy)", ["spoof", "self_signed"],
           {"spoof": "partial", "self_signed": "full"}, ("defenses/web_bot_auth.py",),
           [held("spoof"), fast("self_signed")], 1.0),
    5: rnd(5, "L5 trust policy, freshness window, nonce replay cache", ["spoof", "self_signed", "stale", "fresh"],
           {"spoof": "partial", "self_signed": "partial", "stale": "blocked", "fresh": "blocked"},
           ("defenses/web_bot_auth.py",), [held("spoof", "self_signed", "stale", "fresh")], 0.02),
}

if __name__ == "__main__":
    main(ROUNDS)
