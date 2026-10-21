"""
Round 4 attack — everything at once, plus the moves an adaptive attacker makes (🔴 against operate & audit).

Four parts:

  1. The whole fleet again: the crawler fleet (Round 1) and the agent farm
     (Round 2) run together, so the final scoreboard is the real one.
  2. Score-oracle probing (W4 Ch8). A prober lands robotic sessions in the
     challenge band and reads the reply. Below L4 the reply carries the score,
     so the prober fits the threshold; at L4 the oracle guard removes it and the
     fit is noise.
  3. A new signed vendor appears (agents.newvendor.test). It is honest, signed
     and mandated, but unknown to rules/trusted_operators.json, so it is refused
     until a human onboards it (tools/approve.py onboard-operator) — a false
     positive with a cost, and the drift the ops round is about.

Everything is synthetic and loopback-only (labnet.py via tools/labclient.py).

    python attacks/round4_integrated.py
"""

import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "tools"))
sys.path.insert(0, LAB_DIR)

import labclient  # noqa: E402  (runs the labnet guard on import)
import synthetic_input as si  # noqa: E402
from _common import (CHROME_UA, CLOUD, DROP_SIZE, DROP_SKU, grant_mandate, owner_accounts,  # noqa: E402
                     report, rng_for, summary, target)
from _http_agent import run_session  # noqa: E402


def score_oracle_probe(base, n=60):
    """Land robotic sessions in the challenge band and read the reply. Can the attacker read
    a score back and fit the threshold? (It never solves the challenge, so it buys nothing.)"""
    accts = owner_accounts(6)
    seen = 0
    for i in range(n):
        s = requests.Session()
        ip = CLOUD[i % len(CLOUD)]
        s.headers.update({"User-Agent": CHROME_UA, "X-Lab-Client-IP": ip, "X-Lab-Actor": "bot:score_probe"})
        acct = accts[i % len(accts)]
        s.get(f"{base}/login")
        s.post(f"{base}/api/login", json={"email": acct["email"], "password": acct["password"]}, timeout=10)
        rng = rng_for(f"probe-{i}")
        fp = {"ua": CHROME_UA, "canvas": f"{rng.getrandbits(32):08x}", "webdriver": False}
        s.post(f"{base}/api/telemetry", json={"kind": "capstone", "page": "/checkout", "fp": fp,
                                              "events": si.events_for("agent", rng, 1500, a11y=False)}, timeout=10)
        r = s.post(f"{base}/api/buy", json={"sku": DROP_SKU, "size": DROP_SIZE}, timeout=10)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if isinstance(body, dict) and body.get("score") is not None:
            seen += 1
    return {"attempted": n, "succeeded": 0, "scores_readable": seen,
            "threshold_recoverable": seen > n // 2}


def new_vendor(base, n=5):
    """An honest, signed, mandated cloud agent from a vendor the store has never heard of."""
    accts = owner_accounts(6)
    out = []
    for i in range(n):
        acct = accts[i % len(accts)]
        egress = CLOUD[(i + 60) % len(CLOUD)]
        mandate, _why = grant_mandate(base, acct, "agents.newvendor.test", egress=egress)
        out.append(run_session(base, acct, actor="bot:new_vendor", egress=egress, declared="signed",
                               operator="agents.newvendor.test", sign=True, key_origin="agents.newvendor.test",
                               mandate=mandate, attended=True, can_see=True, fp_seed=f"vendor-{i}"))
    return summary("new_vendor", out, None)


def run(base=None):
    base = target() if base is None else base
    print("Round 4 — integrated attack + adaptation:\n")
    from round1_crawler_fleet import run as crawl_fleet
    from round2_agent_farm import run as agent_farm
    print("--- crawler fleet (as Round 1):")
    crawl_fleet(base)
    print("\n--- agent farm (as Round 2):")
    farm = agent_farm(base)
    print("\n--- score-oracle prober:")
    probe = score_oracle_probe(base)
    print(f"  {probe['scores_readable']}/{probe['attempted']} replies carried a score; "
          f"threshold {'RECOVERABLE' if probe['threshold_recoverable'] else 'not recoverable'} from the replies.")
    print("\n--- a new signed vendor appears (agents.newvendor.test):")
    vend = new_vendor(base)
    report(vend, "orders placed")
    return {"farm": farm, "probe": probe, "new_vendor": vend}


if __name__ == "__main__":
    run()
