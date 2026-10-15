"""
Round checkpoint for W4 Ch3 (Deterrence & Monetization for AI Crawlers). Declares the rounds and
hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's crawlers next to the cohort
    python tools/checkpoint.py --round 3 --level 2    # the same crawlers against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the bare store). Each round runs the crawler that beats
the PREVIOUS round's defense, plus the earlier one to prove it is still held:

    round  defense added                         crawlers run                        what you should see
    -----  ------------------------------------  ----------------------------------  ---------------------------------
      0    none                                  compliant, ignoring LabTrainBot     both take the whole catalogue
      1    published policy (robots, AIPREF,     compliant, ignoring                 compliant leaves with 0%; ignoring
           Content-Signal, RSL)                                                      still takes 100%, every request logged
      2    enforcement on named crawlers         ignoring, stealth Chrome            ignoring refused; stealth takes 100%
      3    poisoned maze (tag, decoys, drip)     stealth, maze-aware stealth         stealth drowns in decoys; aware takes 100%
      4    402 pay-per-crawl                     paying LabTrainBot, free-path leak  paying takes 100% and is billed to the
                                                                                     cent; the leak gets nothing

Next to the crawlers run the starter's 40 shoppers and nine clients that must never be hurt
(tools/personas_ch3.py): 5 prefetching shoppers, 3 text-mode readers and the verified search crawler.
"Hurt" means refused (403), paywalled (402), billed (`crawler-charged`) or served a decoy. The store's
scoreboard counts `paywalled`, `charged` and `mazed` in their own columns (contract 1.6, an ext
setting g.outcome), so the table below the standard scoreboard reports each next to `blocked`.

Defender cost: the median gate time of the shoppers' requests from the decision log, and what the
maze costs (generation time per decoy page, bytes, concurrency-cap hits).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch3  # noqa: E402  (swaps in the chapter's cohort and the `crawl_gov` scenario)
import scoreboard as sb  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

ATTACKS = {
    "compliant": "attacks/round1_compliant_crawler.py",
    "ignoring": "attacks/round1_ignoring_crawler.py",
    "stealth": "attacks/round2_stealth_crawler.py",
    "naive": "attacks/round3_stealth_crawler.py",
    "aware": "attacks/round3_maze_aware_crawler.py",
    "paying": "attacks/round4_paying_crawler.py",
    "leak": "attacks/round4_free_path_leak.py",
}
GATE_MEDIAN_MAX_MS = 25.0           # defender-cost threshold: median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis: a few network round trips per request under a crawler flood
NAIVE_COVERAGE_MAX = 0.25          # the feed link in the footer hands any crawler 20 records before the maze can tag it
COLUMNS = ("requests", "served", "blocked", "paywalled", "charged", "mazed")


# --- the scoreboard, with the chapter's custom outcome columns ----------------------------------

def governance_table(board, markdown=False):
    """paywalled / charged / mazed next to blocked, for the bots, the nine clients you keep, and the shoppers."""
    rows = {}
    for a in board["actors"]:
        key = {"bot": a["actor"], "legit": a["actor"]}.get(a["kind"], "shoppers (all)")
        row = rows.setdefault(key, dict.fromkeys(COLUMNS, 0))
        for c in COLUMNS:
            row[c] += a.get(c, 0) + (a.get("purchased", 0) if c == "served" else 0)
    lines = ["", "crawl governance (the scoreboard's custom outcome columns)" if not markdown else
             "**Crawl governance** (the scoreboard's custom outcome columns)", ""]
    if markdown:
        lines += ["| actor | " + " | ".join(COLUMNS) + " |", "|" + "---|" * (len(COLUMNS) + 1)]
        lines += [f"| {k} | " + " | ".join(str(v[c]) for c in COLUMNS) + " |" for k, v in sorted(rows.items())]
    else:
        lines.append(f"{'actor':<28}" + "".join(f"{c:>11}" for c in COLUMNS))
        lines += [f"{k:<28}" + "".join(f"{v[c]:>11}" for c in COLUMNS) for k, v in sorted(rows.items())]
    return "\n".join(lines)


_render = sb.render


def render(board, markdown=False):
    return _render(board, markdown) + "\n" + governance_table(board, markdown)


sb.render = render          # checkpoint_core calls scoreboard.render(board, markdown) for every round, "before" runs too


def actor_row(board, actor):
    return next((a for a in board["actors"] if a["actor"] == actor), {})


# --- checks --------------------------------------------------------------------------------------

def legit_unharmed(board, results, attacks):
    """Nothing a customer, reader or the search crawler does may be refused, paywalled, billed or mazed."""
    rows = [r for r in results if r["actor"].startswith("legit:")]
    print("\nclients you keep                 served  refused  paywalled  billed  mazed")
    bad = []
    for r in sorted(rows, key=lambda r: r["actor"]):
        print(f"  {r['actor']:<30}{r.get('served', 0):>6}{r.get('blocked', 0):>9}{r.get('paywalled', 0):>11}"
              f"{r.get('charged', 0):>8}{r.get('mazed', 0):>7}")
        if r.get("outcome") == "blocked":
            bad.append(f"{r['actor']} was hurt (refused {r.get('blocked', 0)}, paywalled {r.get('paywalled', 0)}, "
                       f"billed {r.get('charged', 0)}, mazed {r.get('mazed', 0)})")
    search = next(r for r in rows if r["persona"] == "search")
    if search.get("served", 0) < personas_ch3.SEARCH_PAGES:
        bad.append(f"the verified search crawler indexed {search.get('served', 0)} pages, not {personas_ch3.SEARCH_PAGES}")
    shoppers = [a for a in board["actors"] if a["kind"] == "human"]
    unseen = sum(a.get("paywalled", 0) + a.get("charged", 0) + a.get("mazed", 0) for a in shoppers)
    print(f"  shoppers: {board['summary']['humans_hurt']}/{board['summary']['humans']} hurt; "
          f"{unseen} of their requests paywalled, billed or mazed (invisible to the stock scoreboard)")
    if unseen:
        bad.append(f"{unseen} shopper requests were paywalled, billed or mazed")
    return (not bad, "; ".join(bad))


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = sorted(d["ms"] for d in rows)
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    print(f"\ndefender cost (the shoppers' requests, while the crawlers run)\n"
          f"  gate per request: median {median:.2f} ms, p95 {ms[int(len(ms) * 0.95)]:.2f} ms over {len(ms)} requests")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


def decisions(actor):
    return labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": actor})["items"]


def policy_published(board, results, attacks):
    robots = labclient.requests.get(f"{labclient.BASE_URL}/robots.txt", timeout=5).text
    hdrs = labclient.requests.get(f"{labclient.BASE_URL}/", timeout=5).headers
    bad = []
    if "User-agent: LabTrainBot\nDisallow: /" not in robots:
        bad.append("robots.txt has no LabTrainBot group with Disallow: /")
    if not all(k in robots for k in ("Content-Signal:", "Content-Usage:", "License:")):
        bad.append("robots.txt lacks Content-Signal, Content-Usage or License")
    if "Content-Usage" not in hdrs or 'rel="license"' not in hdrs.get("Link", ""):
        bad.append("pages carry no Content-Usage header or Link rel=license")
    if "Disallow: /maze/" not in robots:
        bad.append("robots.txt does not Disallow the maze prefix")
    print(f"\npolicy: robots.txt {len(robots.splitlines())} lines, Content-Usage header {hdrs.get('Content-Usage')!r}")
    return (not bad, "; ".join(bad))


def violations(board, results, attacks):
    n_ign = sum("crawl_policy:robots_violation" in d["signals"] for d in decisions("bot:ignoring"))
    n_comp = sum("crawl_policy:robots_violation" in d["signals"] for d in decisions("bot:compliant"))
    print(f"  robots violations logged: ignoring crawler {n_ign}, compliant crawler {n_comp}")
    bad = []
    if n_ign == 0:
        bad.append("the ignoring crawler's requests are not logged as robots violations")
    if n_comp:
        bad.append(f"the compliant crawler committed {n_comp} robots violations")
    return (not bad, "; ".join(bad))


def stealth_wins(board, results, attacks):
    out = attacks["stealth"]
    print(f"  stealth crawler: {out['coverage']:.0%} of the catalogue (expected: all of it; that is the limit of Round 2)")
    return (out["coverage"] >= 0.9, f"stealth crawler got {out['coverage']:.0%}, expected the whole catalogue")


def maze_budget(board, results, attacks):
    naive, aware = attacks["naive"], attacks["aware"]
    share = naive["maze_pages"] / max(1, naive["requests"])
    stats = labclient.admin("GET", "/lab/crawl/stats")["maze"]
    pages = max(1, stats["pages"])
    row = actor_row(board, "bot:naive")
    print(f"\nmaze: the naive crawler spent {share:.0%} of its {naive['requests']} requests on decoys "
          f"({row.get('mazed', 0)} in the scoreboard's mazed column); the maze-aware crawler got {aware['coverage']:.0%}\n"
          f"  cost  {stats['pages']} decoy pages, {stats['gen_ms_total'] / pages:.2f} ms/page to generate, "
          f"{stats['bytes'] / 1024:.0f} KB served, concurrency cap hit {stats['capped']}x")
    bad = []
    if share < 0.70:
        bad.append(f"the naive crawler spent only {share:.0%} of its budget in the maze (want >= 70%)")
    if naive["coverage"] > NAIVE_COVERAGE_MAX:
        bad.append(f"the naive crawler still took {naive['coverage']:.0%} of the catalogue (want <= {NAIVE_COVERAGE_MAX:.0%})")
    if not row.get("mazed"):
        bad.append("the scoreboard shows no `mazed` outcomes for the naive crawler")
    if aware["coverage"] < 0.9:
        bad.append(f"the maze-aware crawler got {aware['coverage']:.0%}; hygiene should beat a tarpit (the rung's limit)")
    return (not bad, "; ".join(bad))


def ledger(board, results, attacks):
    paying, leak = attacks["paying"], attacks["leak"]
    stats = labclient.admin("GET", "/lab/crawl/stats")["ledger"]
    total = round(stats.get("total", 0.0), 2)
    row = actor_row(board, "bot:paying")
    print(f"\nledger: ${total:.2f} for {row.get('charged', 0)} charged requests against the crawler's own bill "
          f"${paying['spent_usd']:.2f}; {row.get('paywalled', 0)} requests met a 402 first; ledger by operator {stats}")
    bad = []
    if abs(total - paying["spent_usd"]) >= 0.005 or total <= 0:
        bad.append(f"ledger ${total:.2f} != the crawler's bill ${paying['spent_usd']:.2f}")
    if not (row.get("charged") and row.get("paywalled")):
        bad.append("the scoreboard shows no `paywalled`/`charged` outcomes for the paying crawler")
    if leak["succeeded"] and leak["spent_usd"] == 0:
        bad.append(f"the free-path leak rebuilt {leak['coverage']:.0%} of the catalogue for $0: a carrier is not behind the paywall")
    return (not bad, "; ".join(bad))


def rnd(level, description, attacks, expect, solutions, checks, **kw):
    return Round(level=level, description=description, scenario="crawl_gov",
                 attacks={n: ATTACKS[n] for n in attacks}, expect=expect, solutions=solutions,
                 extra_checks=[*checks, legit_unharmed, gate_cost], **kw)


ROUNDS = {
    0: rnd(0, "bare store: nobody asks who is crawling", ["compliant", "ignoring"],
           {"compliant": "full", "ignoring": "full"}, (), []),
    1: rnd(1, "L1 published policy: robots.txt, AIPREF, Content-Signal, RSL", ["compliant", "ignoring"],
           {"compliant": "blocked", "ignoring": "full"}, ("defenses/crawl_policy.py",), [policy_published, violations]),
    2: rnd(2, "L2 enforcement on crawlers you can name", ["ignoring", "stealth"],
           {"ignoring": "blocked", "stealth": "full"}, ("defenses/enforce.py",), [stealth_wins]),
    3: rnd(3, "L3 poisoned maze: hidden link, decoys, tagging, capped drip", ["naive", "aware"],
           {"aware": "full"}, ("defenses/maze.py",), [maze_budget]),
    4: rnd(4, "L4 pay-per-crawl over HTTP 402, every carrier behind it", ["paying", "leak"],
           {"paying": "full", "leak": "blocked"}, ("defenses/paywall.py",), [ledger]),
}

if __name__ == "__main__":
    main(ROUNDS)
