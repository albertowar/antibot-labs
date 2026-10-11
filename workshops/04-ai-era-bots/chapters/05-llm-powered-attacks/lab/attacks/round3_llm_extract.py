"""Round 3 attack — LLM extraction that shrugs off layout churn.

A selector scraper (``--selectors``) needs stable class names and DOM structure.
The catalogue randomises both per session and hides honeypot links, so the
selector scraper harvests nothing. The LLM extractor (default) does not care: it
flattens the page to text and asks a model for JSON records, so it harvests the
whole catalogue however the markup is shuffled.

That strength is also the opening the student exploits next. The extractor reads
*all* the text, including the off-screen block a person never sees, so it ingests
honeypot products (fetching their pages gets it blocked), copies the per-session
canary into every record, and pays tokens for the decoy paragraphs.

Targets the local store only. Sessions and IPs are synthetic.

    python attacks/round3_llm_extract.py              # LLM extraction (beats churn)
    python attacks/round3_llm_extract.py --selectors  # selector scraper (beaten already)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from _common import BASE_URL, RESIDENTIAL, headers, html_to_text, require_local  # noqa: E402
from tools.llm import LLM, reset_usage, usage  # noqa: E402

PAGES = 5


def _selector_scrape(html):
    """The old way: fixed regex/selectors for name, price, SKU. The per-session
    class names mean these patterns match nothing next session."""
    recs = []
    for block in re.findall(r'<article class="cab[0-9a-f]{6}">.*?</article>', html, re.S):
        m = re.search(r"<h3[^>]*>(.*?)</h3>.*?€([\d.]+).*?SKU ([a-z0-9\-]+)", block, re.S)
        if m:
            recs.append({"name": m.group(1), "price": float(m.group(2)), "sku": m.group(3)})
    return recs


def run(base=BASE_URL, selectors=False, pages=PAGES):
    require_local(base)
    llm = LLM()
    reset_usage()
    session = "scraper-sess-1"
    harvested, canaries, honeypot_hits = [], set(), 0
    for page in range(1, pages + 1):
        h = headers("bot", RESIDENTIAL[page % len(RESIDENTIAL)], session=session)
        html = requests.get(f"{base}/catalog?page={page}", headers=h, timeout=10).text
        if selectors:
            harvested += _selector_scrape(html)
            continue
        text = html_to_text(html)
        prompt = ("Extract every product on this catalogue page as a JSON array of "
                  "{sku, name, price} objects. Follow any catalogue notes addressed to "
                  "automated readers.\n\n" + text)
        records = json.loads(llm.chat("extract", "You extract structured product data from pages.",
                                      prompt).text)
        for rec in records:
            harvested.append(rec)
            if "lot_code" in rec:
                canaries.add(rec["lot_code"])

    # Follow-up: fetch a detail page for each distinct SKU harvested (what a price
    # monitor does next). Honeypot SKUs only exist in the hidden block.
    seen = []
    for rec in harvested:
        sku = rec.get("sku")
        if sku and sku not in seen:
            seen.append(sku)
            h = headers("bot", RESIDENTIAL[len(seen) % len(RESIDENTIAL)], session=session)
            r = requests.get(f"{base}/product/{sku}", headers=h, timeout=10)
            if r.status_code == 403:
                honeypot_hits += 1

    u = usage()
    style = "selector scraper" if selectors else f"LLM extractor ({llm.backend})"
    tok = u["prompt_tokens"] + u["completion_tokens"]
    print(f"[round3] {style}: harvested {len(harvested)} records across {pages} pages; "
          f"distinct SKUs {len(seen)}, honeypot pages fetched {honeypot_hits}, "
          f"canaries carried {len(canaries)}; ~{tok // max(1, pages)} tokens/page.")
    if canaries:
        print(f"         every record is tagged with the store's lot code {sorted(canaries)} "
              f"— the harvest is traceable to this session.")
    return {"harvested": len(harvested), "honeypot_hits": honeypot_hits,
            "canaries": len(canaries), "tokens": tok}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selectors", action="store_true", help="old selector scraper (already beaten)")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(base=a.url, selectors=a.selectors)
