"""Run the legitimate cohort against the store and report what happened to it.

    python tools/legit_traffic.py            # all 14 personas, summary per group
    python tools/legit_traffic.py --json     # machine-readable (used by checkpoint.py)

A served request is "allow"; 429 is "limit" (friction); 403 is "challenge" or "block"
depending on the body. A blocked person is a false positive. A blocked verified crawler
is a policy error. A limited crawler is a cost you chose on purpose.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))
sys.path.insert(0, HERE)
from _common import BASE_URL, require_local  # noqa: E402
import personas  # noqa: E402


def run(base: str = BASE_URL, seed: int = 7) -> list[dict]:
    require_local(base)
    rng = random.Random(seed)
    jobs = ([lambda p=p, r=random.Random(seed + i): personas.run_human(p, base, r) for i, p in enumerate(personas.HUMANS)]
            + [lambda p=p: personas.run_non_browser(p, base) for p in personas.NON_BROWSER]
            + [lambda p=p: personas.run_crawler(p, base) for p in personas.CRAWLERS])
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        results = list(ex.map(lambda f: f(), jobs))
    for r in results:
        t = {"allow": 0, "limit": 0, "challenge": 0, "block": 0}
        for o in r["outcomes"]:
            t[o] = t.get(o, 0) + 1
        r["tally"] = t
    return results


def summarize(results: list[dict]) -> None:
    for group in ("humans", "non-browser", "crawlers"):
        print(f"\n{group}")
        for r in results:
            if r["group"] != group:
                continue
            t = r["tally"]
            served = t["allow"]
            total = sum(t.values())
            mark = "✅" if t["block"] == 0 and t["challenge"] == 0 else "❌"
            extra = ""
            if t["limit"]:
                extra += f"  ⚠️ {t['limit']} limited"
            if r.get("skipped"):
                extra += f"  (robots.txt: skipped {r['skipped']} product URLs voluntarily)"
            print(f"  {mark} {r['name']:<24} served {served}/{total}  blocked {t['block']}  challenged {t['challenge']}{extra}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run(a.url)
    if a.json:
        print(json.dumps(res))
    else:
        summarize(res)
