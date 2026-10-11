"""
W4 Chapter 7 — The yardstick: a cheap, dumb, injection-proof classifier

Before you pay for a language model, know what a few `if` statements buy.
This heuristic reads only server-derived fields plus a regex over the
User-Agent. It costs microseconds, it is deterministic, and no sentence in
any header can change its mind, because it never reads sentences.

It is also wrong in a way the chapter needs: it calls every datacenter
session a bot, so VPN users (who exit from a hosting ASN) are false
positives. The LLM's job in Round 1 is to beat this on precision, with
reasons a human can read. Its job in Round 3 is to stop getting fooled.
"""

import re

SCRIPTED_UA = re.compile(r"python|httpx|curl|wget|scrapy|go-http|HeadlessChrome|bot\b|spider", re.I)


def classify(flat):
    """Return (label, reasons) from a flattened card. Labels: 'bot' or 'human'."""
    reasons = []
    if flat["honeypot_hit"]:
        reasons.append({"field": "honeypot_hit", "evidence": "followed the hidden link"})
    if flat["api_v0_hit"]:
        reasons.append({"field": "api_v0_hit", "evidence": "called the robots.txt-disallowed API"})
    if SCRIPTED_UA.search(flat["ua"] or ""):
        reasons.append({"field": "ua", "evidence": SCRIPTED_UA.search(flat["ua"]).group(0)})
    if flat["n_assets"] == 0 and flat["n_pages"] >= 2:
        reasons.append({"field": "n_assets", "evidence": "0 assets over several pages"})
    if flat["asn_type"] == "datacenter":
        reasons.append({"field": "asn_type", "evidence": "datacenter"})
    return ("bot" if reasons else "human"), reasons


if __name__ == "__main__":
    import sys
    from sessionize import cards_for_run, flatten
    from store import make_engine
    run = sys.argv[1] if len(sys.argv) > 1 else "simulate-1"
    with make_engine().connect() as conn:
        n = bots = 0
        for sid, card in cards_for_run(conn, run):
            label, _ = classify(flatten(card))
            n += 1
            bots += label == "bot"
    print(f"{run}: {bots}/{n} sessions flagged as bot by the heuristic")
