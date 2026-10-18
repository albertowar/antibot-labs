"""Round 5 attack: the careful crawler that pays in CPU.

The maze-aware crawler of Round 3 (Chrome User-Agent, residential addresses, no hidden links, no
babble) took the whole catalogue through Round 4: nothing can name it and it never touches the maze.
Round 5 puts a proof of work in front of the catalogue, so this crawler learns to solve it: read the
puzzle in the 403, find a counter, POST it from the same address, retry. Same hygiene, plus a solver.

It shows both sides of the economics:

  * What the gate costs it: hashes and CPU-seconds per product record, and dollars per 1,000 records at
    a cloud vCPU's list price. At 16 bits this is a fraction of a cent. The gate is a floor under the
    cost of crawling, not a wall: pay it and you read everything.
  * What pass scoping does to it. A pass is good for POW_PASS_BUDGET protected requests, for POW_PASS_TTL
    seconds, from one address. So the crawler must pay again every ~20 requests, and a crawler that
    rotates addresses (as Rounds 2-3's did, one per request) pays once per ADDRESS it uses.

  --mode pinned   (default, judged)  one address, one cookie jar: pays once per pass budget
  --mode rotate   a pool of addresses, one jar each: pays once per address, then per budget on each
  --mode share    a pool of addresses and ONE jar: the pass is bound to the address that earned it, so the
                  gate refuses it from every other one and the crawler pays on nearly every request

    python attacks/round5_pow_solving_crawler.py [--mode rotate] [--budget 400]
"""

from __future__ import annotations

import argparse
import json

from _common import AWARE_POOL, CATALOG, CHROME_UA, Crawler, print_report
import pow_client
from labclient import world_pool

# A slice of residential egress no other crawler uses, so a maze tag or a pass earned elsewhere never leaks in.
SOLVER_POOL = world_pool("residential_proxy")[96:120]


class SolvingCrawler(Crawler):
    """The aware crawler with a solver and a cookie jar per address it keeps its pass in."""

    def __init__(self, mode="pinned", **kw):
        pool = SOLVER_POOL[:1] if mode == "pinned" else SOLVER_POOL
        super().__init__("solver", CHROME_UA, pool, obey_robots=False, follow_hidden=False, trap_hints=True,
                         max_depth=20, babble_limit=0.25, label=f"PoW-solving crawler ({mode})", **kw)
        self.mode, self.jars = mode, {}
        self.solves = self.hashes = self.refused = 0
        self.cpu_s = 0.0

    def _jar(self, ip):
        key = "all" if self.mode == "share" else ip
        return self.jars.setdefault(key, type(self.client.http.cookies)())

    def _headers_json(self):
        return [("User-Agent", self.ua), ("Accept", "application/json")]

    def _get(self, path, extra=None):
        ip = self._ip()
        self.client.http.cookies = self._jar(ip)         # a crawler that wants a pass keeps its cookies
        r = self.client.get(path, headers=self._headers(path, extra), ip=ip)
        self.stats["requests"] += 1
        payload = pow_client.payload_of(r)
        if payload is not None:
            self.stats["challenged"] += 1
            counter, tried, cpu = pow_client.solve_payload(payload)
            self.hashes, self.cpu_s, self.solves = self.hashes + tried, self.cpu_s + cpu, self.solves + 1
            if pow_client.redeem(self.client, payload, counter, self._headers_json(), ip=ip):
                r = self.client.get(path, headers=self._headers(path, extra), ip=ip)
                self.stats["requests"] += 1
            else:
                self.refused += 1
        self.stats[str(r.status_code)] += 1
        return r

    def report(self):
        rep = super().report()
        n = max(1, rep["products"])
        per_1k_s = self.cpu_s / n * 1000
        rep.update(mode=self.mode, solves=self.solves, hashes=self.hashes, cpu_s=round(self.cpu_s, 3),
                   challenged=self.stats["challenged"], hashes_per_record=round(self.hashes / n),
                   cpu_ms_per_record=round(self.cpu_s / n * 1000, 2),
                   usd_per_1k_records=round(per_1k_s / 3600 * pow_client.USD_PER_VCPU_HOUR, 6),
                   addresses=len(self.ips if self.mode != "pinned" else self.ips[:1]))
        return rep


def run(budget=400, mode="pinned"):
    c = SolvingCrawler(mode=mode, budget=budget)
    rep = c.crawl()
    print_report(rep)
    print(f"[economics] {rep['solves']} solves ({rep['hashes']:,} hashes, {rep['cpu_s']:.2f} CPU-s) for "
          f"{rep['products']} records: {rep['hashes_per_record']:,} hashes and {rep['cpu_ms_per_record']} ms per record, "
          f"${rep['usd_per_1k_records']:.6f} per 1,000 records at $0.04/vCPU-hour")
    print(f"[scaling] 10 million records at this rate: ~{rep['cpu_s'] / max(1, rep['products']) * 1e7 / 3600:.1f} CPU-hours "
          f"(~${rep['usd_per_1k_records'] * 1e4:.2f}); each extra bit of difficulty doubles it, and your phone shoppers' wait")
    print(json.dumps(rep))
    return rep


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["pinned", "rotate", "share"], default="pinned")
    ap.add_argument("--budget", type=int, default=400, help="request budget")
    a = ap.parse_args()
    run(budget=a.budget, mode=a.mode)
