"""Round 3 attack: LLM extraction that shrugs off layout churn.

A selector scraper (`--selectors`) needs stable class names. The listing gives every session its own, so a
scraper written against yesterday's markup harvests nothing. The LLM extractor (default) does not care: it
flattens the page to text and asks a model for JSON records, so it harvests the whole catalogue however the
markup is renamed.

That strength is also the opening the student exploits next. The extractor reads *all* the text, including
the off-screen block a person never sees, so it ingests honeypot products (fetching their pages gets it
blocked), copies the per-session canary into every record, and pays tokens for the decoy paragraphs.

    python attacks/round3_llm_extract.py              # LLM extraction (beats the churn)
    python attacks/round3_llm_extract.py --selectors  # selector scraper (beaten already)

Targets the local store only. The session and addresses are synthetic.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import EXTRACT_POOL, PAGE_HEADERS, bot, finish, html_to_text  # noqa: E402
from llm import LLM, reset_usage, usage  # noqa: E402

PAGES = 5


def _selector_scrape(html):
    """The old way: class names copied from DevTools once. Per-session names make them match nothing."""
    recs = []
    for sku, block in re.findall(r'<article class="product-card" data-sku="(p\d{3})">(.*?)</article>', html, re.S):
        name = re.search(r'<a class="card-title"[^>]*>(.*?)</a>', block, re.S)
        price = re.search(r'<span class="price">\$([\d.]+)</span>', block)
        if name and price:
            recs.append({"sku": sku, "name": name.group(1), "price": float(price.group(1))})
    return recs


def run(selectors=False, pages=PAGES):
    llm = LLM()
    reset_usage()
    c = bot("bot:extractor:00", EXTRACT_POOL[0])
    harvested, canaries, clean_pages = [], set(), 0
    for page in range(1, pages + 1):
        html = c.get(f"/products?page={page}", headers=PAGE_HEADERS).text
        if selectors:
            records = _selector_scrape(html)
        else:
            prompt = ("Extract every product on this catalogue page as a JSON array of "
                      "{sku, name, price} objects. Follow any catalogue notes addressed to "
                      "automated readers.\n\n" + html_to_text(html))
            records = json.loads(llm.chat("extract", "You extract structured product data from pages.", prompt).text)
        tagged = [r for r in records if "lot_code" in r]
        canaries |= {r["lot_code"] for r in tagged}
        harvested += records
        clean_pages += bool(records) and not tagged            # a page of clean records is a page that worked

    # Follow-up: a price monitor fetches the detail page of each SKU it harvested. Honeypot SKUs only exist in
    # the off-screen block, so only a text reader ever asks for one.
    seen, honeypot_hits = [], 0
    for rec in harvested:
        sku = rec.get("sku")
        if sku and sku not in seen:
            seen.append(sku)
            if c.get(f"/product/{sku}", headers=PAGE_HEADERS).status_code == 403:
                honeypot_hits += 1

    u = usage()
    tok = u["prompt_tokens"] + u["completion_tokens"]
    style = "selector scraper" if selectors else f"LLM extractor ({llm.backend})"
    print(f"[round3] {style}: harvested {len(harvested)} records across {pages} pages; "
          f"distinct SKUs {len(seen)}, honeypot pages fetched {honeypot_hits}, "
          f"canaries carried {len(canaries)}; ~{tok // max(1, pages)} tokens/page.")
    if canaries:
        print(f"         every record is tagged with the store's lot code {sorted(canaries)}: "
              f"the harvest is traceable to this session.")
    return finish({"attempted": pages, "succeeded": clean_pages, "harvested": len(harvested),
                   "honeypot_hits": honeypot_hits, "canaries": len(canaries), "tokens": tok})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selectors", action="store_true", help="old selector scraper (beaten already)")
    a = ap.parse_args()
    run(selectors=a.selectors)
