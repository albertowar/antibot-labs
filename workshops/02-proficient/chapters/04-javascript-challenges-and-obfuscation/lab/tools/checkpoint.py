"""
Round checkpoint for Chapter 4 (JavaScript Challenges & Obfuscation). Declares the rounds and hands
over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run the round's bots next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same bots against level 2 (the "before")
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 (ladder.py, policy.py) first

Every defense is pre-written; Round N = level N. Each round runs every bot introduced so far: the
expectation is "full" (the whole catalogue: 5 listing pages + 120 product records), "partial"
(stopped part-way, the harvester at level 5) or "blocked".

Next to the bots:
  - the store's 40 shoppers browse the catalogue (tools/population.py) and solve the challenge
    the way their browser would (tools/personas_ch4.py). A shopper stopped by the gate fails the
    round, except the no-JavaScript one from level 1 on: an accepted, measured cost.
  - one real Chromium and one real Firefox (Playwright) load the catalogue through the
    interstitial. Either one stopped fails the round: they are the ground truth for the
    shoppers' model, and Firefox is the one NAIVE_ENGINE_CHECK=1 hurts.
  - the defender's cost: the gate's time per request (Server-Timing), the challenge script's size.

Round 3 needs the variant pool: if defenses/secrets/manifest.json is missing, this builds it
(python tools/build_variants.py, which needs Node 24 and `npm ci`).

Needs: pip install -r requirements-browser.txt && python -m playwright install chromium firefox && npm ci
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_ch4  # noqa: E402,F401  (registers the shoppers' challenge hook)
from checkpoint_core import LAB, Round, main  # noqa: E402

# name -> (script, round introduced, first level that stops it, expectation once stopped)
BOTS = {
    "round1_requests_scraper": ("attacks/round1_requests_scraper.py", 0, 1, "blocked"),
    "round1_cookie_forge": ("attacks/round1_cookie_forge.py", 1, 2, "blocked"),
    "round2_python_port": ("attacks/round2_python_port.py", 2, 3, "blocked"),
    "round3_jsdom_solver": ("attacks/round3_jsdom_solver.py", 3, 4, "blocked"),
    "round4_playwright_harvest": ("attacks/round4_playwright_harvest.py", 4, 5, "partial"),
    "round5_resolve_loop": ("attacks/round5_resolve_loop.py", 5, None, None),
}
MANIFEST = os.path.join(LAB, "defenses", "secrets", "manifest.json")


def ensure_pool():
    if not os.path.exists(MANIFEST):
        print("building the variant pool (tools/build_variants.py) ...")
        subprocess.run([sys.executable, os.path.join(HERE, "build_variants.py")], cwd=LAB, check=True)


ensure_pool()          # at import: tools/verify.py imports this module and calls checkpoint_core itself


def bots(n):
    return {name: script for name, (script, introduced, _, _) in BOTS.items() if introduced <= n}


def expect(n):
    out = {}
    for name, (_, introduced, stopped_at, stopped) in BOTS.items():
        if introduced <= n:
            out[name] = stopped if stopped_at is not None and n >= stopped_at else "full"
    return out


def real_browsers(board, results, attacks):
    """One real Chromium and one real Firefox load the catalogue through the interstitial."""
    from playwright.sync_api import sync_playwright
    bad, lines = [], []
    with sync_playwright() as p:
        for name, kind in (("chromium", p.chromium), ("firefox", p.firefox)):
            try:
                browser = kind.launch()
            except Exception as e:                  # browser not installed
                bad.append(f"{name}: cannot launch ({str(e).splitlines()[0][:80]}); python -m playwright install {name}")
                continue
            page = labclient.browser_context(browser, f"human:browser:{name}").new_page()
            try:
                page.goto(f"{labclient.BASE_URL}/products")
                page.wait_for_selector(".product-card", timeout=20000)
                status = page.evaluate("fetch('/api/products?page=2').then(r => r.status)")
                lines.append(f"  {name:<9} through the challenge, then /api/products -> {status}")
                if status != 200:
                    bad.append(f"{name}: /api/products -> {status}")
            except Exception:
                text = page.text_content("#challenge-status") if page.query_selector("#challenge-status") else "?"
                lines.append(f"  {name:<9} STOPPED at the interstitial: {text}")
                bad.append(f"{name} stopped by the challenge")
            browser.close()
    print("\nreal browsers")
    print("\n".join(lines))
    return (not bad, "; ".join(bad))


def costs(board, results, attacks):
    gate = [a.get("gate_ms") for a in attacks.values() if isinstance(a, dict) and a.get("gate_ms") is not None]
    sizes = []
    for f in os.listdir(os.path.join(LAB, "demo_site", "static", "js", "variants")) if os.path.isdir(
            os.path.join(LAB, "demo_site", "static", "js", "variants")) else []:
        sizes.append(os.path.getsize(os.path.join(LAB, "demo_site", "static", "js", "variants", f)))
    personas_ch4.print_js(results)
    print("defender cost: gate median per request (from the bots' 200s): "
          + (f"{sorted(gate)[len(gate) // 2]:.3f} ms" if gate else "-")
          + (f"; obfuscated variant {sorted(sizes)[len(sizes) // 2] / 1024:.1f} KB (median of {len(sizes)})" if sizes else ""))
    return (True, "")


def make_round(n, description):
    return Round(level=n, description=description, scenario="browse", attacks=bots(n), expect=expect(n),
                 allowed_fp=("no_js",) if n >= 1 else (), bot_success_max=1.0,
                 extra_checks=[costs, real_browsers], solutions=("defenses/ladder.py", "defenses/policy.py"))


ROUNDS = {
    0: make_round(0, "no challenge: the catalogue is open"),
    1: make_round(1, "inline JS sets a fixed cookie"),
    2: make_round(2, "signed, session-bound, single-use challenge"),
    3: make_round(3, "polymorphic, obfuscated variant pool"),
    4: make_round(4, "environment-bound answer"),
    5: make_round(5, "clearance budget"),
}

if __name__ == "__main__":
    main(ROUNDS)
