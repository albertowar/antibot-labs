"""
Chapter 4 shoppers: what a person's browser does when the catalogue answers with the JS challenge.

The shoppers in tools/population.py are Python, not browsers. Where a real browser would run the
challenge script, this hook does the equivalent work, honestly: it reads the challenge out of the
interstitial, computes the answer the way that browser's engine would (so the server genuinely
verifies it), sleeps for what the person's device would have taken, posts the answer and reloads.

    persona          engine (Error.stack style)    device time per solve   solves?
    ---------------  ----------------------------  ----------------------  -----------------
    Chrome desktops  V8                            0.05-0.3 s              yes
    Firefox, Safari  SpiderMonkey / JavaScriptCore 0.05-0.3 s              yes
    iOS phones       JavaScriptCore                0.2-0.8 s               yes
    Android phones   V8                            0.4-1.6 s (budget CPU)  yes
    no_js            -                             -                       no: the interstitial is a wall

The engine comes from the persona's real browser, not from the server's guess
(env_integrity.expected_engine), so NAIVE_ENGINE_CHECK=1 hurts the Firefox and Safari shoppers
exactly as it would hurt real ones. The device times are assumptions, not measurements: the
checkpoint's real-browser check (one Chromium, one Firefox) is the ground truth next to them.

To compute the answer for an obfuscated variant, the hook reads the server's own answer key
(defenses/secrets/manifest.json). That is lab code standing in for a browser that would simply
run the variant; no attack script may do the same.

The persona result gains a `js` entry: {"scheme", "verified", "wait_s"} or {"no_js": True}.

    python tools/personas_ch4.py [--scenario browse] [--n 40]     # shoppers with the hook on
"""

import json
import os
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
LAB = os.path.abspath(os.path.join(HERE, ".."))
if LAB not in sys.path:
    sys.path.insert(0, LAB)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL  # noqa: E402

PAYLOAD = re.compile(r"window\.__ch = (\{.*?\});")
COOKIE_KEYS = re.compile(r"var k = (\[[^\]]*\])")


def engine_of(p):
    from defenses import variants
    return variants.ENGINE_V8 if p.browser[0] == "chrome" else variants.ENGINE_OTHER


def device_seconds(p, rng):
    kind = p.browser[-1]
    lo, hi = {"android": (0.4, 1.6), "ios": (0.2, 0.8)}.get(kind, (0.05, 0.3))
    return rng.uniform(lo, hi)


def _reload(p, client, r):
    path = r.url.replace(BASE_URL, "")
    r2 = client.get(path, browsers.headers_for(p.browser, "link", BASE_URL, BASE_URL + "/"), allow_redirects=False)
    r.__dict__.update(r2.__dict__)                           # the hook cannot return a response: swap its contents


def js_hook(p, client, r):
    """After each page load: if the gate served the interstitial, behave like the browser would."""
    if r.status_code != 403 or 'id="challenge-status"' not in r.text:
        return
    if not p.js:
        p.result["js"] = {"no_js": True}
        return                                               # nothing runs: the wall stays a wall
    rng = random.Random(f"{p.actor}:{time.time()}")
    keys = COOKIE_KEYS.search(r.text)
    if keys:                                                 # level 1: the inline script sets a cookie
        client.set_cookie("js_ok", "".join(reversed(json.loads(keys.group(1)))))
        p.result["js"] = {"scheme": "cookie", "verified": True, "wait_s": 0.0}
        return _reload(p, client, r)
    m = PAYLOAD.search(r.text)
    if not m:
        return
    from defenses import js_challenge, variants
    ch = json.loads(m.group(1))
    if ch["script"] == "/jsc/l2.js":
        chain, probe = variants.L2_CHAIN, variants.L2_PROBE
    else:
        chain, probe = js_challenge.pool()[ch["script"].rsplit("/", 1)[1][:-3]]
    env = (variants.probe_width(probe), True, engine_of(p)) if ch.get("env") else None
    wait = device_seconds(p, rng)
    time.sleep(wait)
    hdrs = [(k, v) for k, v in browsers.headers_for(p.browser, "post", BASE_URL, r.url) if k.lower() != "content-type"]
    v = client.post("/api/challenge/verify", headers=hdrs + [("Content-Type", "application/json")],
                    json={"type": "js", "answer": {"token": ch["token"], "answer": variants.expected_answer(ch["nonce"], chain, env),
                                                   "solve_ms": round(wait * 1000, 1)}})
    p.result["js"] = {"scheme": "signed", "verified": v.status_code == 200, "wait_s": round(wait, 2)}
    if v.status_code == 200:
        _reload(p, client, r)


def install():
    if js_hook not in population.PAGE_HOOKS:
        population.PAGE_HOOKS.append(js_hook)


install()


def print_js(results):
    rows = {}
    for r in results:
        row = rows.setdefault(r["persona"], {"n": 0, "solved": 0, "failed": 0, "no_js": 0, "waits": []})
        row["n"] += 1
        js = r.get("js")
        if not js:
            continue
        row["no_js"] += bool(js.get("no_js"))
        row["solved"] += bool(js.get("verified"))
        row["failed"] += js.get("verified") is False
        if js.get("wait_s"):
            row["waits"].append(js["wait_s"])
    print(f"\n{'persona':<16}{'n':>4}{'solved':>8}{'failed':>8}{'no JS':>7}{'median wait':>13}")
    for name, row in sorted(rows.items()):
        waits = sorted(row["waits"])
        med = f"{waits[len(waits) // 2]:.2f} s" if waits else "-"
        print(f"{name:<16}{row['n']:>4}{row['solved']:>8}{row['failed']:>8}{row['no_js']:>7}{med:>13}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="browse")
    ap.add_argument("--n", type=int, default=None)
    args = ap.parse_args()
    print_js(population.run(args.scenario, n=args.n))
