"""
Round checkpoint for W4 Ch1 (AI Crawlers: Landscape & Identification). Declares the rounds and
hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's crawlers next to the cohort
    python tools/checkpoint.py --round 3 --level 2    # the same crawlers against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the bare store). Each round runs the crawler that beats
the PREVIOUS round's defense, plus the earlier crawlers to prove they are still stopped:

    round  defense added                           crawlers run                          what you should see
    -----  --------------------------------------  ------------------------------------  ---------------------------------
      0    none                                    honest GPTBot                         takes the whole catalog
      1    registry + published robots.txt         honest GPTBot, GPTBot ignoring        both get nothing; the OAI-SearchBot
                                                   robots.txt, impersonated search bot   impersonator takes everything
      2    verification (ranges, FCrDNS)           + fake-PTR Googlebot, stealth Chrome  impersonators get nothing; the
                                                                                         stealth crawler takes everything
      3    behaviour signature                     + polite 30-address crawler           stealth stopped; the polite crawler
                                                                                         gets some; LocalSearchBot refused
      4    identity x purpose policy               same crawlers                         LocalSearchBot limited, not refused

Next to the crawlers, the starter's 40 shoppers browse and buy, and nine automated clients you want
to keep run too (tools/personas_ch1.py): four non-browser tools and five declared crawlers, one of them
a small search engine that cannot prove who it is. `hurt` is a client that met a 403; `limited` is a 429
(friction you chose). LocalSearchBot's refusal at Round 3 is the chapter's documented false positive.

Defender cost: the median and p95 gate time of the shoppers' catalog requests from the decision log,
while the crawlers hammer the same store (history recording, parsing, signature and policy).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch1  # noqa: E402  (the chapter's cohort, the `crawl_mix` scenario and the assets PAGE_HOOK)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

ATTACKS = {
    "gptbot": "attacks/round0_declared_crawler.py",
    "gptbot_ignores": "attacks/round0_declared_crawler.py --ignore-robots",
    "impersonator": "attacks/round1_impersonate_searchbot.py",
    "fake_ptr": "attacks/round1_impersonate_searchbot.py --token Googlebot --fake-ptr",
    "stealth": "attacks/round2_stealth_chrome.py",
    "polite": "attacks/round3_polite_distributed.py",
    "polite_cookies": "attacks/round3_polite_distributed.py --cookies --pool home_eu",
}
GATE_MEDIAN_MAX_MS = 25.0           # defender-cost threshold: median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis: a few network round trips per request under a crawler flood
KEEP = ("verified_googlebot", "verified_oai_searchbot", "verified_gptbot", "verified_claudebot")


def welcome(localsearch):
    """The nine automated clients you keep: tools and declared crawlers. localsearch: 'ok' | 'refused' | 'limited'."""
    def check(board, results, attacks):
        rows = {r["persona"]: r for r in results if r["actor"].startswith("legit:")}
        print("\nwelcome automation (not shoppers)      served  limited  refused")
        bad = []
        for name, r in sorted(rows.items()):
            extra = f"   (robots.txt: skipped {r['skipped']})" if r.get("skipped") else ""
            print(f"  {name:<34}{r.get('served', 0):>6}{r.get('limited', 0):>9}{r.get('blocked', 0):>9}{extra}")
        for name in KEEP:
            if rows[name].get("limited"):
                bad.append(f"{name} was rate-limited {rows[name]['limited']}x: a verified crawler should not meet a budget")
        ls = rows["localsearchbot"]
        got = "refused" if ls.get("blocked") else ("limited" if ls.get("limited") else "ok")
        if localsearch == "refused" and got != "refused":
            bad.append(f"localsearchbot was {got}; the blunt Round 3 mapping should refuse it (the documented false positive)")
        if localsearch == "limited" and got != "limited":
            bad.append(f"localsearchbot was {got}; Round 4 should give it a budget (limited, never refused)")
        return (not bad, "; ".join(bad))
    return check


def crawlers(**want):
    """want: attack name -> 'full' | 'partial' | 'blocked' (printed beside what each crawler took)."""
    def check(board, results, attacks):
        print("\ncrawlers                  product pages taken   expected")
        for name in want:
            out = attacks.get(name) or {}
            print(f"  {name:<22}{out.get('succeeded', '?'):>6} /{out.get('attempted', '?'):<4} ({out.get('coverage', '?')}%)   {want[name]}")
        return (True, "")
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    print(f"\ndefender cost (the shoppers' requests, while the crawlers run)\n  gate per request: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} requests")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


def rnd(level, description, attacks, expect, solutions, welcome_check, **kw):
    return Round(level=level, description=description, scenario="crawl_mix",
                 people=personas_ch1.personas, attacks={name: ATTACKS[name] for name in attacks}, expect=expect, solutions=solutions,
                 extra_checks=[crawlers(**expect), welcome_check, gate_cost], **kw)


ROUNDS = {
    0: rnd(0, "bare store: nobody asks who is crawling", ["gptbot"], {"gptbot": "full"}, (), welcome("ok")),
    1: rnd(1, "L1 registry + published robots.txt", ["gptbot", "gptbot_ignores", "impersonator"],
           {"gptbot": "blocked", "gptbot_ignores": "blocked", "impersonator": "full"},
           ("defenses/ladder.py", "defenses/crawler_registry.py", "data/crawl_policy.robots"), welcome("ok")),
    2: rnd(2, "L2 verification: published ranges + forward-confirmed rDNS", ["gptbot_ignores", "impersonator", "fake_ptr", "stealth"],
           {"gptbot_ignores": "blocked", "impersonator": "blocked", "fake_ptr": "blocked", "stealth": "full"},
           ("defenses/ladder.py", "defenses/crawler_verify.py"), welcome("ok")),
    3: rnd(3, "L3 behaviour signature", ["impersonator", "stealth", "polite", "polite_cookies"],
           {"impersonator": "blocked", "stealth": "blocked", "polite": "partial", "polite_cookies": "full"},
           ("defenses/ladder.py", "defenses/crawl_signature.py"), welcome("refused"), allowed_fp=("localsearchbot",),
           legit_hurt_max=1),   # LocalSearchBot refused: the documented false positive
    4: rnd(4, "L4 identity x purpose policy", ["impersonator", "stealth", "polite", "polite_cookies"],
           {"impersonator": "blocked", "stealth": "blocked", "polite": "partial", "polite_cookies": "full"},
           ("defenses/ladder.py", "defenses/crawl_policy.py"), welcome("limited"),
           legit_hurt_max=1),   # LocalSearchBot limited: the scoreboard counts a 429 as a stop; none is refused
}

if __name__ == "__main__":
    main(ROUNDS)
