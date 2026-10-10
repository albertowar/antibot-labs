"""
Chapter 6 — Round 4 Attack B: pay humans to solve it (Section 6.5)

Objective: any puzzle a person can read, a farm can read. The bot fetches
each challenge, sends the image to a (simulated) solving service, and
submits the answer 10–40 simulated seconds later. Like most bot traffic
that has met Chapter 3, it sends every request through a rotating proxy
pool, so the IP that fetched the image is not the IP that submits it.

Goal: 10 vouchers, solved in parallel, at most 3 farm jobs per voucher.

Expected results:
  - DEFENSE_LEVEL=3 → ~9/10 vouchers, about $0.01 in solving fees
  - DEFENSE_LEVEL=4, fixed signals → ~0: issuer ≠ submitter plus a solve
    time in the farm band
  - DEFENSE_LEVEL=4 with --sticky-ip → gets through. Pinning one proxy per
    voucher removes the mismatch; what's left is the farm's price and
    latency. That is where a CAPTCHA's job ends (debrief).

Run:
    python attacks/round4_solver_farm.py
    python attacks/round4_solver_farm.py --sticky-ip
"""

import argparse
import random
from concurrent.futures import ThreadPoolExecutor

from common import BOT_NET, bot, new_challenge, random_ip, redeem, require_local, summary, unlock
from farm import Farm

GOAL, JOBS_PER_VOUCHER = 10, 3


def one_voucher(farm, sticky, rng):
    c = bot(actor="farm")
    unlock(c)
    reasons = []
    for _ in range(JOBS_PER_VOUCHER):
        cid, _ = new_challenge(c)
        if cid is None:
            return redeem(c)[0] == 200, ["no CAPTCHA"]
        answer = farm.solve_image(cid)
        if not sticky:   # the proxy pool hands out a new exit IP per request
            c.headers["X-Lab-Client-IP"] = random_ip(BOT_NET, rng)
        status, body = redeem(c, cid, answer)
        if status == 200:
            return True, reasons
        reasons.append(body.get("error"))
    return False, reasons


def run(sticky=False, seed=None):
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    farm, rng = Farm(seed), random.Random(seed)
    with ThreadPoolExecutor(GOAL) as pool:
        results = list(pool.map(lambda _: one_voucher(farm, sticky, rng), range(GOAL)))
    reasons = {}
    for _, rs in results:
        for r in rs:
            reasons[r] = reasons.get(r, 0) + 1
    return summary("round4_solver_farm" + ("_sticky" if sticky else ""), GOAL,
                   sum(ok for ok, _ in results), farm_jobs=farm.jobs,
                   spent=farm.spent, reasons=reasons)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sticky-ip", action="store_true", help="one proxy IP per voucher")
    args = p.parse_args()
    s = run(sticky=args.sticky_ip)
    print(f"=== Round 4B: human solving farm ({'sticky' if args.sticky_ip else 'rotating'} IPs) ===")
    print(f"  vouchers: {s['successes']}/{s['attempts']} · {s['farm_jobs']} farm jobs · "
          f"${s['spent']:.3f} spent")
    for reason, n in s["reasons"].items():
        print(f"  rejected ×{n}: {reason}")
