"""
Chapter 6, Round 0: what does a hash cost?

Before defending with CPU time, measure it. This prints your single-core Python rate (what
the Round 2 attacker gets), your all-core rate (the Round 3 solver pool), and what 16, 20 and
22 bits cost at those rates, at p50 and p95. It does not need the store.

Then open http://127.0.0.1:5000/lab/pow/bench in your browser: that is what a real user pays,
with the store's own JavaScript solver. A GPU running hashcat does ~20,000 MH/s of SHA-256;
keep that number in mind for Round 3.

    python attacks/round0_bench.py
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import Tally, close_pool, solve_parallel  # noqa: E402

from defenses.pow_core import hash_rate, hashes_at_percentile  # noqa: E402


def run(seconds=1.0):
    single = hash_rate(seconds)
    tally = Tally("round0_bench", wanted=1)
    started = time.perf_counter()
    for i in range(3):  # a few 18-bit solves across all cores
        solve_parallel({"nonce": f"bench-{i}", "difficulty": 18}, tally)
    wall = time.perf_counter() - started
    close_pool()
    return {"single_hps": single, "pool_hps": tally.hashes / wall, "cores": min(os.cpu_count() or 2, 8)}


if __name__ == "__main__":
    print("=== Round 0: how fast can this laptop hash? ===")
    r = run()
    print(f"  Python, 1 core:        {r['single_hps'] / 1e6:6.2f} MH/s")
    print(f"  Python, {r['cores']} processes:  {r['pool_hps'] / 1e6:6.2f} MH/s\n")
    print("  bits   expected hashes   1 core p50 / p95      all cores p50 / p95")
    for bits in (16, 20, 22):
        p50, p95 = hashes_at_percentile(bits, .5), hashes_at_percentile(bits, .95)
        print(f"  {bits:>4}   {2 ** bits:>15,}   {p50 / r['single_hps']:6.2f} s / {p95 / r['single_hps']:6.2f} s    "
              f"{p50 / r['pool_hps']:6.2f} s / {p95 / r['pool_hps']:6.2f} s")
    print("\n  Now open /lab/pow/bench in your browser and write down the browser's MH/s.")
    print(json.dumps({k: round(v, 1) if isinstance(v, float) else v for k, v in r.items()}))
