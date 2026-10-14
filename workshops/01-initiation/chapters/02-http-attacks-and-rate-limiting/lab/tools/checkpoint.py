"""
Round checkpoint for Chapter 2 (HTTP Attacks & Rate Limiting). Declares the rounds and hands
over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attacks against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first
    python tools/checkpoint.py --all --markdown       # every round (the reference table)

Every round measures two things: how much the attacker got (catalog scraped, or login attempts
the limiter let through), and which of the 40 shoppers the defense stopped. The shoppers run
the `rush` scenario (and `rush_login` once logins matter), compressed so the phones that share
one carrier-NAT address actually meet the per-IP limit. A round's `allowed_fp` names the
personas it is allowed to hurt: that list IS the false-positive cost of the layer.

There is no challenge type in this chapter, so a challenge verdict is enforced as a block. The
rate limits answer 429; the monitor in Round 1 blocks nothing at all.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch2  # noqa: E402,F401  (registers the `rush` and `rush_login` scenarios)
from checkpoint_core import Round, main  # noqa: E402
from labclient import admin  # noqa: E402


def _hurt(results, persona):
    return [r for r in results if r["persona"] == persona and r.get("outcome") in ("blocked", "stuck_on_challenge")]


def monitor_tags_bot(board, results):
    """Round 1's lesson: the monitor sees the flood (and blocks nothing)."""
    rows = admin("GET", "/lab/decisions", params={"actor": "bot:", "limit": 5000})["items"]
    tagged = any("flood_monitor:" in (d.get("signals") or "") for d in rows)
    blocked = [d for d in rows if d.get("action") in ("rate_limit", "block")]
    return tagged and not blocked, (
        "expected the flood to be tagged flood_monitor:* and nothing blocked; "
        f"tagged={tagged}, blocked={len(blocked)}")


def cgnat_pays(board, results):
    """The shared-address cost: a per-IP limit stops at least one phone behind the carrier NAT."""
    n = len(_hurt(results, "mobile_cgnat"))
    return n >= 1, f"expected the per-IP limit to stop at least one mobile_cgnat shopper, stopped {n}"


def typo_shopper_ok(board, results):
    """The per-account cap must tolerate a real fat-finger: 2 wrong + 1 right is under the limit."""
    rows = [r for r in results if r["actor"] == personas_ch2.TYPO_ACTOR]
    bad = [r for r in rows if r.get("outcome") not in ("logged_in", "bought", "browsed")]
    return not bad, f"the fat-finger shopper was stopped by account_limit: {[r.get('outcome') for r in bad]}"


SOL = ("defenses/ladder.py",)

ROUNDS = {
    1: Round(level=1, description="naive flood vs a monitor that only watches", scenario="rush",
             attacks={"flood": "attacks/round1_flood.py",
                      "login_flood": "attacks/round1_flood.py --login"},
             expect={"flood": "full", "login_flood": "full"},
             allowed_fp=(), extra_checks=[monitor_tags_bot],
             solutions=SOL + ("defenses/flood_monitor.py",)),
    2: Round(level=2, description="boundary burst vs a fixed window", scenario="rush",
             attacks={"flood": "attacks/round1_flood.py",
                      "boundary": "attacks/round2_boundary.py"},
             expect={"flood": "partial", "boundary": "full"},
             allowed_fp=("mobile_cgnat",),
             solutions=SOL + ("defenses/fixed_window.py",)),
    3: Round(level=3, description="a patient client vs a token bucket", scenario="rush",
             attacks={"boundary": "attacks/round2_boundary.py",
                      "paced_login": "attacks/round3_paced_login.py"},
             expect={"boundary": "partial", "paced_login": "full"},
             allowed_fp=("mobile_cgnat",), extra_checks=[cgnat_pays],
             solutions=SOL + ("defenses/rate_limit.py", "defenses/sliding_window.py")),
    4: Round(level=4, description="rotation and brute force vs endpoint and account keys", scenario="rush_login",
             attacks={"login_flood": "attacks/round1_flood.py --login",
                      "brute": "attacks/round4_rotate.py --brute",
                      "rotate": "attacks/round4_rotate.py",
                      "xff": "attacks/round4_rotate.py --xff",
                      "v6": "attacks/round4_rotate.py --pool cloud_v6"},
             expect={"login_flood": "partial", "brute": "blocked", "rotate": "full", "xff": "full", "v6": "full"},
             allowed_fp=("mobile_cgnat",), extra_checks=[typo_shopper_ok],
             solutions=SOL + ("defenses/endpoint_limit.py", "defenses/account_limit.py")),
    5: Round(level=5, description="spoofed headers and rotation vs trusted proxy and prefix keys",
             scenario="rush_login",
             attacks={"xff": "attacks/round4_rotate.py --xff",
                      "v6": "attacks/round4_rotate.py --pool cloud_v6",
                      "fleet": "attacks/round4_rotate.py",
                      "residential": "attacks/round5_residential.py"},
             expect={"xff": "partial", "v6": "partial", "fleet": "full", "residential": "full"},
             allowed_fp=("mobile_cgnat",),
             solutions=SOL + ("defenses/client_ip.py", "defenses/trusted_proxy.py", "defenses/prefix_limit.py")),
}

if __name__ == "__main__":
    main(ROUNDS)
