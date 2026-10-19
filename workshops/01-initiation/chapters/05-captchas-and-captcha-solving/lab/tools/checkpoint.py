"""
Round checkpoint for Chapter 5 (Price the Puzzle). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set the level, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first
    python tools/checkpoint.py --round 3 --level 2    # the same attacks one level down (the "before")
    python tools/checkpoint.py --all --markdown       # every round (the expected-results table)

Each round reports BOTH sides. The bots: which attacks got through (vouchers, accounts, dollars
spent on a farm). The shoppers (tools/population.py + tools/personas_ch5.py): 40 people who sign
up and claim the voucher, with the two screen-reader users, the no-JavaScript visitor, the
deep-linkers and the Wi-Fi -> cellular hopper named, because a CAPTCHA's false positives are
exactly those people. Then the defender's cost: siteverify, image generation and answer checking
in milliseconds (from the decision log).

A round FAILS until you have fixed its TODOs (the attack still gets through), or run it with --catch-up.
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_ch5  # noqa: E402  (registers the signup scenario and the widget hook)
import population  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402


def shoppers(board, results):
    """Report: who signed up, who met a CAPTCHA, who was lost (the false-positive column)."""
    personas_ch5.print_summary(results)
    return True, ""


def hurt_persona(name, want=True):
    """The false positive this round is about: `name` is hurt (want) or untouched (not want)."""
    def check(board, results):
        hurt = [r for r in results if r["persona"] == name and r.get("outcome") in population.HURT]
        total = [r for r in results if r["persona"] == name]
        if want and not hurt:
            return False, f"expected {name} shoppers to be hurt this round (none of {len(total)} was)"
        if not want and hurt:
            return False, f"{len(hurt)} of {len(total)} {name} shoppers were hurt, and should not be"
        return True, ""
    return check


def rate_at_most(name, limit):
    def check(board, results, attacks):
        out = attacks.get(name) or {}
        rate = out.get("succeeded", 0) / max(1, out.get("attempted", 1))
        return rate <= limit, f"{name}: {rate:.0%} succeeded, expected at most {limit:.0%}"
    return check


def hopper_stepped_up(board, results):
    """Round 4's false positive that heals: the phone that changed network is stepped up, then passes."""
    h = [r for r in results if r["persona"] == "hopper"]
    ok = all(r.get("outcome") == "redeemed" and r.get("captchas", 0) >= 2 for r in h)
    return ok, "the hopper should have met a second CAPTCHA (issuer != submitter) and then passed"


def defender_cost(board, results):
    """Report: what the defense cost per request, from the decision log."""
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000})["items"]
    print(f"\n{'defender cost (ms)':<22}{'n':>6}{'median':>9}{'p95':>9}")
    series = {"gate (all requests)": [d["ms"] for d in rows]}
    for key, label in (("siteverify_ms", "siteverify"), ("captcha_gen_ms", "image generation"), ("captcha_check_ms", "answer check")):
        series[label] = [d["extra"][key] for d in rows if key in (d.get("extra") or {})]
    for label, vals in series.items():
        if vals:
            vals = sorted(vals)
            print(f"{label:<22}{len(vals):>6}{statistics.median(vals):>9.2f}{vals[min(len(vals) - 1, int(.95 * len(vals)))]:>9.2f}")
    return True, ""


def solve_histogram(board, results):
    import solve_times
    print("\n" + solve_times.render(solve_times.rows()))
    return True, ""


ROUNDS = {
    0: Round(level=0, description="no CAPTCHA anywhere: the baseline every round is compared with",
             attacks={"register": "attacks/round0_mass_register.py"}, expect={"register": "full"},
             scenario="signup", extra_checks=[shoppers, defender_cost]),
    1: Round(level=1, description="provider token on sign-up: the integration bugs are the bypass",
             attacks={"register": "attacks/round0_mass_register.py", "bypass": "attacks/round1_bypass.py"},
             expect={"register": "blocked", "bypass": "blocked"}, scenario="signup",
             allowed_fp=("no_js",),
             extra_checks=[hurt_persona("no_js"), shoppers, defender_cost],
             solutions=("defenses/siteverify.py",)),
    2: Round(level=2, description="image CAPTCHA on the voucher, answer kept server-side",
             attacks={"bypass": "attacks/round1_bypass.py", "cookie_replay": "attacks/round2_cookie_replay.py"},
             expect={"bypass": "blocked", "cookie_replay": "blocked"}, scenario="signup",
             allowed_fp=("no_js", "screen_reader"),
             extra_checks=[hurt_persona("screen_reader"), shoppers, defender_cost],
             solutions=("defenses/challenge_store.py",)),
    3: Round(level=3, description="hardened images: the targeted solver drops from ~100% to a few percent",
             attacks={"cookie_replay": "attacks/round2_cookie_replay.py", "ocr": "attacks/round3_ocr.py"},
             expect={"cookie_replay": "blocked"}, scenario="signup",
             allowed_fp=("no_js", "screen_reader"),
             extra_checks=[rate_at_most("ocr", 0.35), hurt_persona("screen_reader"), shoppers, defender_cost],
             solutions=("defenses/captcha_generator.py",)),
    4: Round(level=4, description="solver signals and serve-on-risk: retry and rotating farm stopped, sticky farm is the residual",
             attacks={"retry": "attacks/round4_retry_ocr.py", "farm": "attacks/round4_solver_farm.py",
                      "farm_sticky": "attacks/round4_solver_farm.py --sticky-ip"},
             expect={"retry": "blocked", "farm": "blocked", "farm_sticky": "full"}, scenario="signup",
             allowed_fp=("no_js",),
             extra_checks=[hurt_persona("screen_reader", want=False), hopper_stepped_up, shoppers, defender_cost, solve_histogram],
             solutions=("defenses/solver_signals.py",)),
}

if __name__ == "__main__":
    main(ROUNDS)
