"""
Chapter 5, Round 4 attack B: pay humans to solve it (section 5.5).

Objective: any puzzle a person can read, a farm can read. The bot fetches each challenge, sends
the image to a (simulated) solving service, and submits the answer 10-40 simulated seconds later.
Like most bot traffic that has met Chapter 2, it sends every request through a rotating proxy
pool, so the IP that fetched the image is not the IP that submits it.

Goal: 10 vouchers, solved in parallel, at most 3 farm jobs per voucher.

Expected:
  DEFENSE_LEVEL=3                    ~9/10 vouchers, about $0.01 in solving fees
  DEFENSE_LEVEL=4, fixed signals     ~0: issuer != submitter plus a solve time in the farm band
  DEFENSE_LEVEL=4 with --sticky-ip   gets through. Pinning one proxy per voucher removes the
                                     mismatch; what's left is the farm's price and latency.
                                     That is where a CAPTCHA's job ends (debrief).

    python attacks/round4_solver_farm.py
    python attacks/round4_solver_farm.py --sticky-ip
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402
import argparse  # noqa: E402
import random  # noqa: E402
from concurrent.futures import ThreadPoolExecutor  # noqa: E402

from farm import Farm  # noqa: E402

GOAL, JOBS_PER_VOUCHER = 10, 3


def one_voucher(farm, sticky, rng, proxies):
    """Open the offer, hit the CAPTCHA, buy an answer, submit it; a wrong answer buys another job."""
    if sticky:
        c = ck.bot("farm", ip=rng.choice(proxies), rng=rng)
    else:
        c = ck.bot("farm", rotate=proxies, rng=rng)          # the proxy pool hands out a new exit IP per request
    ck.unlock(c)
    for _ in range(JOBS_PER_VOUCHER):
        status, body = ck.redeem(c)
        if status == 200:
            return True
        payload = body.get("error", {}).get("payload")
        if not payload:
            return False
        answer = farm.solve_image(payload["id"])
        if ck.answer_challenge(c, payload["id"], answer).status_code == 200 and ck.redeem(c)[0] == 200:
            return True
    return False


def run(sticky=False, seed=None):
    farm, rng = Farm(seed), random.Random(seed)
    proxies = labclient.world_pool("residential_proxy")          # 400 exit IPs: a repeat is a 1-in-400 accident
    with ThreadPoolExecutor(GOAL) as pool:
        results = list(pool.map(lambda i: one_voucher(farm, sticky, random.Random(rng.random()), proxies), range(GOAL)))
    return ck.report("round4_solver_farm" + ("_sticky" if sticky else ""), GOAL, sum(results), farm_jobs=farm.jobs,
                     spent=round(farm.spent, 4), reasons=ck.reasons("bot:farm", "captcha_reason"))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sticky-ip", action="store_true", help="one proxy IP per voucher")
    args = p.parse_args()
    s = run(sticky=args.sticky_ip)
    print(f"=== Round 4B: human solving farm ({'sticky' if args.sticky_ip else 'rotating'} IPs) ===")
    print(f"  vouchers: {s['succeeded']}/{s['attempted']} · {s['farm_jobs']} farm jobs · ${s['spent']:.3f} spent")
    for reason, n in sorted(s["reasons"].items(), key=lambda kv: -kv[1])[:6]:
        print(f"  refused x{n}: {reason}")
    ck.emit(s)
