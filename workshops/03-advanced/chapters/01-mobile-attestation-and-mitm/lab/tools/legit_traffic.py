"""
W3 Ch1 — Legitimate-traffic simulator

Runs every persona in tools/personas.py through the genuine app flow (log in,
then buy the drop) against the live store, and reports how each one was treated.
It runs next to every attack so each round shows the false-positive bill beside
the bots it stopped.

    run() -> [ {persona, device, stage, outcome, reasons, score_ms}, ... ]

Returns, it does not print. tools/checkpoint.py prints the summary.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "attacks"))

import personas  # noqa: E402
from lab import BASE_URL, ensure_local  # noqa: E402
from mobile_client import MobileApp, outcome_of  # noqa: E402


def _score_ms(response):
    st = response.headers.get("server-timing", "")
    if "dur=" in st:
        try:
            return float(st.split("dur=")[1].split(",")[0])
        except ValueError:
            return None
    return None


def run():
    ensure_local()
    results = []
    for a in personas.accounts():
        app = MobileApp(base=BASE_URL, device=a["device"], serial=a["email"], egress=a["egress"])
        login = app.login(a["email"], a["password"])
        if login.status_code != 200:
            results.append({"persona": a["persona"], "device": a["device"], "stage": "login",
                            "outcome": "error", "reasons": [f"login {login.status_code}"], "score_ms": None})
            app.close()
            continue
        resp = app.buy("lab-runner-9")
        outcome, _, reasons = outcome_of(resp)
        results.append({"persona": a["persona"], "device": a["device"], "stage": "buy",
                        "outcome": outcome, "reasons": reasons, "score_ms": _score_ms(resp)})
        app.close()
    return results


if __name__ == '__main__':
    for r in run():
        print(f"  {r['persona']:<20} {r['device']:<16} {r['outcome']:<10} {r['reasons'][:1]}")
