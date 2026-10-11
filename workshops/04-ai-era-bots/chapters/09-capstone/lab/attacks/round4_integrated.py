"""
Round 4 attack — everything at once, plus the moves an adaptive attacker makes (🔴 against operate & audit).

Three parts:

  1. The whole fleet again: the crawler fleet (Round 1) and the agent farm
     (Round 2) run together, so the final scoreboard is the real one.
  2. Score-oracle probing (W4 Ch6). A prober sends ~200 cheap checkout attempts
     and reads the reply. If the reply carries the score (L<4), it fits the
     threshold and tunes a session to sit one point under the challenge band.
     At L4 the oracle guard removes the score, so the fit is noise.
  3. A new signed vendor appears (agents.newvendor.test). It is honest and
     signed, but unknown to trusted_operators.json, so it is challenged until a
     human onboards it (tools/approve.py onboard-operator) — a false positive
     with a cost, and the drift the ops round is about.

    python attacks/round4_integrated.py
"""

import os
import statistics
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
from _common import CLOUD, Cost, fleet_identity, owner_accounts, report, rng_for, summary, target  # noqa: E402
from _http_agent import run_session  # noqa: E402
import httpsig  # noqa: E402


def score_oracle_probe(base, n=200):
    """Can the attacker read a score back? Fit the challenge threshold from the replies."""
    rng = rng_for("r4_probe")
    accts = owner_accounts(6)
    seen_scores = 0
    s = requests.Session()
    for i in range(n):
        acct = accts[i % len(accts)]
        sess = requests.Session()
        sess.headers.update({"User-Agent": "Mozilla/5.0 (probe)", "X-Lab-Egress": CLOUD[i % len(CLOUD)],
                             "X-Lab-Actor": "bot:score_probe"})
        sess.get(f"{base}/login")
        sess.post(f"{base}/api/login", json={"email": acct["email"], "password": acct["password"]}, timeout=10)
        r = sess.post(f"{base}/api/checkout", json={"sku": "lab-runner-9"}, timeout=10)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if isinstance(body, dict) and body.get("score") is not None:
            seen_scores += 1
    return {"probes": n, "scores_readable": seen_scores,
            "threshold_recoverable": seen_scores > n // 2}


def new_vendor(base, n=5):
    """An honest, signed cloud agent from a vendor the store has never heard of."""
    rng = rng_for("r4_vendor")
    accts = owner_accounts(6)
    key = os.path.join(LAB_DIR, "data", "keys", "newvendor.pem")
    out = []
    for i in range(n):
        acct = accts[i % len(accts)]
        from _common import grant_mandate
        mandate, _ = grant_mandate(base, acct, "agents.newvendor.test", egress=CLOUD[(i + 60) % len(CLOUD)])
        out.append(run_session(base, acct, actor="newvendor", egress=CLOUD[(i + 60) % len(CLOUD)],
                               declared="signed", operator="agents.newvendor.test", key=key, mandate=mandate,
                               attended=True, can_see=True, fp_seed=f"vendor-{i}"))
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
    print(f"  {probe['scores_readable']}/{probe['probes']} replies carried a score; "
          f"threshold {'RECOVERABLE' if probe['threshold_recoverable'] else 'not recoverable'} from the replies.")
    print("\n--- a new signed vendor appears (agents.newvendor.test):")
    vend = new_vendor(base)
    report(vend, "orders placed")
    return {"farm": farm, "probe": probe, "new_vendor": vend}


if __name__ == "__main__":
    run()
