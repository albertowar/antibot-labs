"""
Round checkpoint for Chapter 3 (Headers, User-Agent & Client Hints). Declares the rounds and hands over
to checkpoint_core.

    python tools/checkpoint.py --round 3              # set the level, run every scraper next to the 40 shoppers
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first
    python tools/checkpoint.py --all --markdown       # every round (the expected-results table)

Every round runs the same set of scrapers against that round's level, so you see the whole attack by defense
matrix grow one diagonal at a time. A scraper is expected to get through (`full`) until the level that is
built to stop it (`blocked`). Next to them, three measures of the other side:

  - the shoppers (tools/population.py + tools/personas_ch3.py): who was stopped who should not have been;
    the stale-Chrome shopper is the one to watch, because it is "suspicious" (score 20) from level 1 on
  - the real-browser profiles (tools/profiles, replayed by tools/replay_profiles.py): zero stopped
  - the defender's cost: the gate's time per replayed request, from Server-Timing

The two Playwright scrapers need `pip install -r requirements-browser.txt` and
`python -m playwright install chromium`. No browser? `SKIP_BROWSER=1 python tools/checkpoint.py --round 3`.
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch3  # noqa: E402,F401  (registers the shoppers' Accept-CH behaviour)
import replay_profiles  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402

SKIP_BROWSER = bool(os.environ.get("SKIP_BROWSER"))

SCRAPERS = {                                    # name -> script, and the first level that stops it
    "naive": ("attacks/round1_naive_requests.py", 1),
    "fake_ua": ("attacks/round2_fake_ua.py", 2),
    "copied": ("attacks/round3_devtools_copy.py", 3),
    "spoof": ("attacks/round4_client_hints_spoof.py", 4),
}
BROWSERS = {
    "headless": ("attacks/round5_playwright_ua_override.py --no-override", 1),
    "override": ("attacks/round5_playwright_ua_override.py", 3),
}


def attacks_at(level, scrapers=True, browsers=True):
    """(attacks, expect) for a checkpoint at `level`: every scraper, each blocked from its own level on."""
    specs = dict(SCRAPERS) if scrapers else {}
    if browsers and not SKIP_BROWSER:
        specs.update(BROWSERS)
    attacks = {name: script for name, (script, _) in specs.items()}
    expect = {name: ("blocked" if level >= first else "full") for name, (_, first) in specs.items()}
    return attacks, expect


def report_profiles(board, results):
    """Real browsers must never be stopped, and the gate's cost per request is reported next to it."""
    out = replay_profiles.run()
    replay_profiles.print_run(out)
    stopped = [r for r in out if r["status"] != 200]
    times = [r["gate_ms"] for r in out if r["gate_ms"] is not None]
    if times:
        p95 = statistics.quantiles(times, n=20)[-1] if len(times) >= 2 else times[0]
        print(f"\n  Defender cost on these requests: median {statistics.median(times):.2f} ms, p95 {p95:.2f} ms "
              f"(the gate: Ctx build + every check)")
    return not stopped, "a real browser's headers were stopped: " + ", ".join(f"{r['profile']} {r['path']}" for r in stopped)


def report_suspicious(board, results):
    """Report only: shoppers whose average score reached the 'monitor' band without being stopped."""
    rows = [r for r in board["actors"] if r["kind"] == "human" and r["avg_score"] >= 15]
    for r in rows:
        print(f"\n  suspicious but served: {r['actor']} averaged score {r['avg_score']} over {r['requests']} requests")
    return True, ""


def templates_agree(board, results):
    problems = replay_profiles.compare_templates()
    return not problems, "tools/browsers.py disagrees with tools/profiles:\n" + "\n".join(problems)


def round_at(level, description, **kw):
    attacks, expect = attacks_at(level, kw.pop("scrapers", True), kw.pop("browsers", True))
    return Round(level=level, description=description, attacks=attacks, expect=expect, scenario="browse",
                 extra_checks=[report_profiles, report_suspicious] + kw.pop("extra", []),
                 solutions=("defenses/ladder.py",), **kw)


ROUNDS = {
    0: round_at(0, "recon: nothing is wired, every scraper gets the catalog", browsers=False, extra=[templates_agree]),
    1: round_at(1, "User-Agent parsing: the naive scraper and headless Chrome are stopped"),
    2: round_at(2, "presence and Fetch Metadata: a Chrome UA on default headers is stopped"),
    3: round_at(3, "Client Hints and header order: copied browser headers and the UA override are stopped"),
    4: round_at(4, "Accept-CH negotiation: consistent static hints are stopped"),
    5: round_at(4, "a real browser with a UA override: already stopped, but only by what its brand list leaks", scrapers=False),
}

if __name__ == "__main__":
    main(ROUNDS)
