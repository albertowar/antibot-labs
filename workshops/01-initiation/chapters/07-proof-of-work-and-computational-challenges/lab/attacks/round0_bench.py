"""
Chapter 7 — Round 0: what does a hash cost? (Section 7.7)

Before defending with CPU time, measure it. This prints:

  - your single-core Python rate (what the Round 2 attacker gets)
  - your all-core rate (what the Round 3 solver pool gets)
  - what 16, 20 and 22 bits cost at those rates, at p50 and p95

Then open http://localhost:5000/pow-bench in your browser and compare: that
is what a *real user* pays, with the store's own JavaScript solver.

Expected: Python ≈ 0.3-1.5 MH/s per core depending on the laptop; the
browser solver is in the same range per worker. A GPU running hashcat does
~20,000 MH/s of SHA-256. Keep that number in mind for Round 3.

Run (no demo site needed):
    python attacks/round0_bench.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from _common import Tally, close_pool, solve_parallel  # noqa: E402
from pow_core import hash_rate, hashes_at_percentile  # noqa: E402


def run(seconds=1.0):
    single = hash_rate(seconds)
    tally = Tally("bench", wanted=1)
    started = time.perf_counter()
    for i in range(3):  # a few 18-bit solves across all cores
        solve_parallel({"nonce": f"bench-{i}", "difficulty": 18}, tally)
    wall = time.perf_counter() - started
    close_pool()
    return {"single_hps": single, "pool_hps": tally.hashes / wall,
            "cores": min(os.cpu_count() or 2, 8)}


if __name__ == "__main__":
    print("=== Round 0: how fast can this laptop hash? ===")
    r = run()
    print(f"  Python, 1 core:           {r['single_hps'] / 1e6:6.2f} MH/s")
    print(f"  Python, {r['cores']} processes:     {r['pool_hps'] / 1e6:6.2f} MH/s\n")
    print("  bits   expected hashes   1 core p50 / p95      all cores p50 / p95")
    for bits in (16, 20, 22):
        p50, p95 = hashes_at_percentile(bits, .5), hashes_at_percentile(bits, .95)
        print(f"  {bits:>4}   {2 ** bits:>15,}   "
              f"{p50 / r['single_hps']:6.2f} s / {p95 / r['single_hps']:6.2f} s    "
              f"{p50 / r['pool_hps']:6.2f} s / {p95 / r['pool_hps']:6.2f} s")
    print("\n  Now open http://localhost:5000/pow-bench and write down the browser's MH/s.")
