"""
Chapter 8 — Round Checkpoint (Section 8.5)

Run at the end of every round. It wipes the store, replays every attack
introduced so far and every legitimate persona, then measures BOTH sides:

  - bot traffic:   trapped or not, compared with the expected result
  - real users:    any trap hit, block, dropped signup or hidden review is a
                   false positive
  - defender cost: trap-check time per request (Server-Timing)

Fell behind? `--catch-up` copies the reference fixes for the TODO rounds up
to N (solutions/roundN/*.py) into defenses/, keeping a .bak of your file. The
demo site reloads by itself. Then restart it with the round's level:
    cd demo_site && DEFENSE_LEVEL=<N> python app.py

Run:
    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 2 --catch-up
    python tools/checkpoint.py --round 3 --skip-browser    # no Playwright scripts
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
import time
import urllib.request

import legit_traffic
import scoreboard

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(LAB, "attacks"))

from _lab import BASE_URL, require_local  # noqa: E402

# script, first round it runs in, needs a browser, first level that traps it (None = never)
ATTACKS = [
    ("round0_recon", 0, False, 1),          # fills every field, like round 1
    ("round1_form_spammer", 1, False, 1),
    ("round1b_markup_aware", 1, False, 2),
    ("round2_playwright_form", 2, True, None),
    ("round3_crawler", 3, False, 3),
    ("round3b_polite_crawler", 3, True, None),
    ("round4_verify_signup", 4, False, 1),
]
CATALOG_SIZE = 12
SOLUTIONS = {2: ["form_traps.py"], 3: ["crawl_traps.py"]}


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def get(path):
    with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=5) as r:
        return json.loads(r.read())


def post(path):
    request = urllib.request.Request(f"{BASE_URL}{path}", method="POST")
    with urllib.request.urlopen(request, timeout=5) as r:
        return json.loads(r.read())


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(LAB, "attacks", f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catch_up(round_no):
    """Install the reference solutions for rounds 1..round_no (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(LAB, round_no)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")
    if installed:
        time.sleep(3)                                # let Flask's reloader restart the app
        for _ in range(20):
            try:
                return get("/trap-check")
            except OSError:
                time.sleep(0.5)
    return None


def judge_attack(name, first_trapped, level, result, counters):
    """Return (ok, what happened, what should have happened) for one attack script."""
    hits = sum(scoreboard.trap_hits(counters).values())
    should_trap = first_trapped is not None and level >= first_trapped
    expectation = "trapped" if should_trap else "gets through"

    if "products" in result:                                    # a crawler
        got = len([p for p in result["products"] if p <= CATALOG_SIZE])
        honey = " + honey product" if any(p > CATALOG_SIZE for p in result["products"]) else ""
        text = f"{hits} trap hits, scraped {got}/{CATALOG_SIZE}{honey}"
        trapped, evaded = hits > 0, hits == 0 and got == CATALOG_SIZE
    else:                                                       # a form bot
        attempts = counters.get("signup_attempts", 0)
        created = counters.get("signup_created", 0)
        trapped = attempts > 0 and created == 0
        evaded = attempts > 0 and created == attempts and hits == 0
        if "conclusions" in result:                             # round 4
            published = counters.get("review_published", 0)
            text = (f"bot concludes {result['conclusions']}, reviews published {published}, "
                    f"accounts active {created}/{attempts}")
            fooled = set(result["conclusions"]) == {"success"}
            return trapped and published == 0 and fooled, text, "trapped, and it can't tell"
        text = (f"{created}/{attempts} signups created "
                f"(bot believes {result['reported_ok']}/{result['attempts']})")
    return (trapped if should_trap else evaded), text, expectation


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required="--restore" not in sys.argv, choices=range(0, 5))
    parser.add_argument("--skip-browser", action="store_true", help="skip the Playwright scripts")
    parser.add_argument("--catch-up", action="store_true",
                        help="apply the reference fixes for rounds <= N first")
    parser.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    args = parser.parse_args()
    if args.restore:
        restored = labnet.restore(LAB)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0
    require_local()

    if args.catch_up:
        catch_up(args.round)
    try:
        check = get("/trap-check")
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    level = check["level"]
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ Expected DEFENSE_LEVEL={args.round}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={args.round} python app.py")
        return 1
    if level == 4 and (check["response_mode"], check["sanction_key"]) != ("quarantine", "session"):
        print(f"❌ The Round 4 checkpoint expects the final configuration. You are on "
              f"RESPONSE_MODE={check['response_mode']} SANCTION_KEY={check['sanction_key']}.")
        print("     cd demo_site && DEFENSE_LEVEL=4 RESPONSE_MODE=quarantine SANCTION_KEY=session python app.py")
        return 1
    if level >= 2 and check["honeypot"]["hide"] == "offscreen":
        print("⚠️  The Round 2 TODO in defenses/form_traps.py is not fixed yet: expect false positives.\n")
    if level >= 3 and not check["robots_disallow"]:
        print("⚠️  The Round 3 TODO in defenses/crawl_traps.py is not fixed yet: expect false positives.\n")

    post("/lab/reset")
    failures = 0

    print("Bot traffic")
    results = {}
    for name, first_round, needs_browser, first_trapped in ATTACKS:
        if first_round > args.round:
            continue
        if needs_browser and args.skip_browser:
            print(f"  ⏭️  {name:<24} skipped (--skip-browser)")
            continue
        results[name] = (load_attack(name).run(), first_trapped)

    print_rows = []
    legit = legit_traffic.run(skip_browser=args.skip_browser)
    actors = get("/lab/summary")["actors"]
    for name, (result, first_trapped) in results.items():
        ok, text, expectation = judge_attack(name, first_trapped, level, result, actors.get(name, {}))
        failures += not ok
        print_rows.append(f"  {'✅' if ok else '❌'} {name:<24} {text} (expected: {expectation})")
    print("\n".join(print_rows))

    print("\nReal users (simulated personas)")
    hurt = 0
    for r in legit:
        found = legit_traffic.problems(r, actors.get(r["persona"], {}))
        hurt += bool(found)
        print(f"  {'❌' if found else '✅'} {r['persona']:<22} " + ("; ".join(found) or "ok"))
    failures += bool(hurt)
    print(f"  → {hurt}/{len(legit)} personas hurt")

    print("\nDefender cost")
    print(scoreboard.cost_line(get("/lab/summary")["timings_ms"]))

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. "
              "Read the notes above, or ask your instructor.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
