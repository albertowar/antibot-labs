"""
Round checkpoint for W2 Ch5 (TLS & Network Fingerprinting). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run every bot next to the shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same bots against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N: level 0 is the bare store (every request is fingerprinted and
logged, nothing is refused) and each level adds one TLS layer (defenses/ladder.py). Every round
runs EVERY attacker, so you see what the current layers stop and what still gets through:

    attacker                      first level that stops it
    round1_naive_requests         1  (ja4_denylist: python-requests is on the list)
    round1_cipher_tweak           2  (tls_family: a Chrome UA on a ClientHello no browser sends)
    round2_impit_chrome           3  (h2_fingerprint: Chrome's TLS on Rust's HTTP/2)
    round3_curl_cffi_chrome       4  (browser_proof: no JavaScript engine ever ran)
    round4_playwright_chromium    never (a real browser; the next chapters' problem)

Each attacker makes 10 requests to /api/products through the TLS edge (fingerproxy), and the
expectation is "full" (>= 90 % served) or "blocked" (<= 10 %).

Next to the attackers, two groups of shoppers measure what each layer costs real people:
  - the store's 40 shoppers (tools/personas_ch5.py, `tls_browse`) present the claimed fingerprint of
    their browser; a refused shopper fails the round, except `no_js` from Round 4 on (it can never
    earn the engine proof: an accepted, measured cost);
  - the real clients, with real handshakes through the edge: partner_api, corporate_proxy, a real
    Chromium and a real Firefox (and WebKit when installed). Any refusal fails the round except
    corporate_proxy from Round 2 on, which must show as the layer's documented cost.

Defender cost: the gate time per request from the decision log (Ctx build, enrichers, every check).

This checkpoint starts its own TLS edge on a free port (tools/tls_edge.py), so it never collides with
the one you may have running in another terminal. Set TLS_EDGE_URL to use yours instead.
Needs: python tools/get_fingerproxy.py once, and for the browsers
python -m playwright install chromium firefox
"""

import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch5  # noqa: E402  (registers the `tls_browse` scenario and the engine PAGE_HOOK)
import tls_edge  # noqa: E402
from checkpoint_core import LAB, Round, main, run_attack  # noqa: E402
import labclient  # noqa: E402

# name -> (script, the first level that stops it; None = never)
BOTS = {
    "round1_naive_requests": ("attacks/round1_naive_requests.py", 1),
    "round1_cipher_tweak": ("attacks/round1_cipher_tweak.py", 2),
    "round2_impit_chrome": ("attacks/round2_impit_chrome.py", 3),
    "round3_curl_cffi_chrome": ("attacks/round3_curl_cffi_chrome.py", 4),
    "round4_playwright_chromium": ("attacks/round4_playwright_chromium.py", None),
}
CA_FILE = os.path.join(LAB, "certs", "tls.crt")
GATE_MEDIAN_MAX_MS = 10.0       # the defender-cost threshold: median gate time per request


def timed_attack(script):
    """An attack through the TLS edge: start the edge on first use, run the script, add its wall time."""
    def go():
        tls_edge.ensure()
        t0 = time.perf_counter()
        out = run_attack(script) or {}
        out["seconds"] = round(time.perf_counter() - t0, 1)
        return out
    return go


def real_clients(with_browsers=True):
    def go():
        edge = tls_edge.ensure()
        rows = personas_ch5.run_real_clients(edge, CA_FILE, with_browsers)
        ran = [r for r in rows if r["status"] is not None]
        return {"attempted": len(ran), "succeeded": sum(r["status"] == 200 for r in ran), "rows": rows}
    return go


def expectation(name, level):
    first = BOTS[name][1]
    return "full" if first is None or level < first else "blocked"


def p95(values):
    return statistics.quantiles(values, n=20)[-1] if len(values) >= 2 else values[0]


def bots_as_expected(level):
    """Every attacker lands exactly where the ladder says (the checkpoint's `expect` also judges it)."""
    def check(board, results, attacks):
        print("\nattackers                       served   first block")
        bad = []
        for name in BOTS:
            out = attacks.get(name) or {}
            print(f"  {name:<28}{out.get('succeeded', '?'):>4}/{out.get('attempted', '?'):<5} {out.get('first_block') or '-'}"
                  f"   ({out.get('seconds', '?')} s)")
            want = expectation(name, level)
            got = out.get("succeeded", 0) / out["attempted"] if out.get("attempted") else None
            if got is None or (want == "full") != (got >= 0.9) or (want == "blocked" and got > 0.1):
                hint = (" (is this machine's python-requests JA4 known? run python tools/capture_fingerprints.py)"
                        if name == "round1_naive_requests" and want == "blocked" else "")
                bad.append(f"{name}: expected {want}, served {out.get('succeeded')}/{out.get('attempted')}{hint}")
        return (not bad, "; ".join(bad))
    return check


def shoppers(level):
    def check(board, results, attacks):
        print("\n40 shoppers (claimed fingerprint)    people  refused")
        for persona, (users, refused) in sorted(personas_ch5.summarize(results).items()):
            print(f"  {persona:<32}{users:>7}{refused:>9}")
        nojs = [r for r in results if r["persona"] == personas_ch5.NO_JS]
        want = "blocked" if level >= 4 else "bought"
        wrong = [r for r in nojs if r.get("outcome") != want]
        return (not wrong, f"the no-JavaScript shopper should be {want} at level {level}, got {[r.get('outcome') for r in wrong]}")
    return check


def real_client_accounting(level):
    def check(board, results, attacks):
        problems, report = personas_ch5.judge((attacks.get("real_clients") or {}).get("rows", []), level)
        print("\nreal clients (measured handshakes)")
        for persona, line, signals in report:
            print(f"  {persona:<18}{line}" + (f"   {signals}" if signals else ""))
        ran = [r for r in (attacks.get("real_clients") or {}).get("rows", []) if r["status"] is not None]
        if not any(r["persona"] == "chromium_user" for r in ran):
            problems.append("chromium_user did not run: python -m playwright install chromium")
        return (not problems, "; ".join(problems))
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000})["items"]
    ms = [d["ms"] for d in rows if d["phase"] == "request"]
    if not ms:
        return (False, "no decisions in the log")
    median = statistics.median(ms)
    print(f"\ndefender cost\n  gate per request: median {median:.2f} ms, p95 {p95(ms):.2f} ms over {len(ms)} requests")
    return (median < GATE_MEDIAN_MAX_MS, f"gate median {median:.2f} ms > {GATE_MEDIAN_MAX_MS} ms")


def make_round(n, description, solutions):
    return Round(level=n, description=description, scenario="tls_browse",
                 attacks={**{name: timed_attack(script) for name, (script, _) in BOTS.items()}, "real_clients": real_clients()},
                 expect={name: expectation(name, n) for name in BOTS},
                 allowed_fp=(personas_ch5.NO_JS,) if n >= 4 else (), bot_success_max=1.0,
                 extra_checks=[bots_as_expected(n), shoppers(n), real_client_accounting(n), gate_cost],
                 solutions=solutions)


ROUNDS = {
    0: make_round(0, "instrument: every request is fingerprinted and logged, nobody is refused", ()),
    1: make_round(1, "L1 JA4 denylist of HTTP libraries", ("defenses/ladder.py", "defenses/ja4_denylist.py")),
    2: make_round(2, "L2 the UA's browser must match the TLS family", ("defenses/ladder.py", "defenses/tls_family.py")),
    3: make_round(3, "L3 the HTTP/2 preface must match the TLS family", ("defenses/ladder.py", "defenses/h2_fingerprint.py")),
    4: make_round(4, "L4 browser TLS needs a JavaScript engine of the same family", ("defenses/ladder.py", "defenses/browser_proof.py")),
}

if __name__ == "__main__":
    main(ROUNDS)
