"""
Chapter 7 shoppers: what a person's browser does when the store answers with the PoW interstitial.

The shoppers in tools/population.py are Python, not browsers. Where a real browser would run
pow.js, this hook does the equivalent work: read the challenge out of the interstitial, solve
it for real (so the server genuinely verifies it), then SLEEP for what the person's device would
have taken (hashes / device rate), POST the answer and reload the page. A shopper whose device
would need longer than PATIENCE_S gives up and leaves: that shopper counts as hurt.

    persona        device                                   solves?
    -------------  ---------------------------------------  ----------------------------------
    desktops, VPN  a laptop browser, 4 workers: DESKTOP_MHS yes
    iOS phones     DESKTOP_MHS / 4                          yes
    Android phones DESKTOP_MHS / 16 (a budget phone)        yes, if it is quick enough
    no_js          JavaScript off                           no: the interstitial is a wall

The phone ratios are assumptions, not measurements. Replace DESKTOP_MHS with your own
/lab/pow/bench number (Round 0): `export DESKTOP_MHS=2.2`.

The persona result gains a `pow` entry: {"bits", "tried", "wait_s", "gave_up"}.

    python tools/personas_ch7.py [--scenario browse] [--n 40]     # shoppers with the PoW hook on
"""

import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL  # noqa: E402
from pow_client import solve  # noqa: E402

DESKTOP_MHS = float(os.environ.get("DESKTOP_MHS", "4.0"))
PATIENCE_S = float(os.environ.get("PATIENCE_S", "5.0"))
PAYLOAD = re.compile(r'<script type="application/json" id="pow-payload">(.*?)</script>', re.S)


def device_rate(p):
    """Hashes per second of the person's device; 0 means no JavaScript."""
    if not p.js:
        return 0.0
    kind = p.browser[-1]
    return DESKTOP_MHS * 1e6 / {"android": 16, "ios": 4}.get(kind, 1)


def pow_hook(p, client, r):
    """After each page load: if the gate served the interstitial, behave like the browser would."""
    if r.status_code != 403 or "pow-payload" not in r.text:
        return
    rate = device_rate(p)
    if not rate:
        p.result["pow"] = {"gave_up": False, "no_js": True}
        return                                               # nothing runs: the wall stays a wall
    challenge = json.loads(PAYLOAD.search(r.text).group(1))
    bits = int(challenge["difficulty"])
    started = time.perf_counter()
    counter, tried = solve(challenge["nonce"], bits, max_hashes=int(rate * PATIENCE_S))
    if counter is None:                                      # would take longer than they will wait
        time.sleep(max(0.0, PATIENCE_S - (time.perf_counter() - started)))
        p.result["pow"] = {"bits": bits, "tried": tried, "wait_s": PATIENCE_S, "gave_up": True}
        return
    wait = tried / rate
    time.sleep(max(0.0, wait - (time.perf_counter() - started)))
    # pow.js uses fetch(): same User-Agent and cookies as the page, JSON body (L3 binds the pass to IP + User-Agent)
    hdrs = [(k, v) for k, v in browsers.headers_for(p.browser, "post", BASE_URL, r.url) if k.lower() != "content-type"]
    v = client.post("/api/challenge/verify", json={"type": "pow", "answer": {"challenge": challenge, "counter": counter}},
                    headers=hdrs + [("Content-Type", "application/json")])
    p.result["pow"] = {"bits": bits, "tried": tried, "wait_s": round(wait, 2), "gave_up": False, "verified": v.status_code == 200}
    if v.status_code != 200:
        return
    path = r.url.replace(BASE_URL, "")
    r2 = client.get(path, browsers.headers_for(p.browser, "link", BASE_URL, BASE_URL + "/"), allow_redirects=False)
    r.__dict__.update(r2.__dict__)                           # the hook cannot return a response: swap its contents


def install():
    if pow_hook not in population.PAGE_HOOKS:
        population.PAGE_HOOKS.append(pow_hook)


install()


def pow_summary(results):
    """Per persona: shoppers who paid, bits seen, median wait, who gave up (for the checkpoint)."""
    rows = {}
    for r in results:
        row = rows.setdefault(r["persona"], {"n": 0, "solved": 0, "gave_up": 0, "no_js": 0, "bits": [], "waits": []})
        row["n"] += 1
        pw = r.get("pow")
        if not pw:
            continue
        row["no_js"] += bool(pw.get("no_js"))
        row["gave_up"] += bool(pw.get("gave_up"))
        row["solved"] += bool(pw.get("verified"))
        if pw.get("bits"):
            row["bits"].append(pw["bits"])
            row["waits"].append(pw["wait_s"])
    return rows


def print_pow(results):
    print(f"\n{'persona':<16}{'n':>4}{'solved':>8}{'gave up':>9}{'no JS':>7}{'max bits':>10}{'median wait':>13}")
    for name, row in sorted(pow_summary(results).items()):
        waits = sorted(row["waits"])
        med = f"{waits[len(waits) // 2]:.2f} s" if waits else "-"
        print(f"{name:<16}{row['n']:>4}{row['solved']:>8}{row['gave_up']:>9}{row['no_js']:>7}{max(row['bits'], default='-'):>10}{med:>13}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="browse")
    ap.add_argument("--n", type=int, default=None)
    args = ap.parse_args()
    out = population.run(args.scenario, n=args.n)
    print_pow(out)
