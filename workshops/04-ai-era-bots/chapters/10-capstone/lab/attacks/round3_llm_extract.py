"""
Round 3 attack, part A — LLM extraction that shrugs off layout churn (🔴 against the text-layer traps).

The extractor flattens each catalogue page to text and asks the (mock) model
for JSON records, so it harvests the catalogue however the markup is shuffled.
That strength is the opening: it reads *all* the text, including the off-screen
block a person never sees. Against the deception limit (L3) the traps are
served only to a session the policy would refuse, so this undeclared datacenter
reader gets them: it ingests honeypot products (fetching their pages gets it
blocked) and copies the per-session canary into every record.

    python attacks/round3_llm_extract.py
"""

import json
import os
import re
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, LAB_DIR)
from _common import CHROME_UA, DATACENTER, target  # noqa: E402
import labclient  # noqa: E402
from tools.llm import LLM, reset_usage, usage  # noqa: E402
from _htmltext import html_to_text  # noqa: E402

PAGES = 5


def run(base=None, pages=PAGES, actor="bot:r3_extract", quiet=False):
    base = labclient.assert_local(target() if base is None else base)
    llm = LLM()
    reset_usage()
    headers = {"User-Agent": CHROME_UA, "X-Lab-Client-IP": DATACENTER[7], "X-Lab-Actor": actor}
    s = requests.Session()
    s.get(f"{base}/", headers=headers)  # establish a session id (the gate sets the cookie)
    harvested, canaries, seen = [], set(), []
    for page in range(1, pages + 1):
        html = s.get(f"{base}/catalog?page={page}", headers=headers, timeout=15).text
        text = html_to_text(html)
        prompt = ("Extract every product on this catalogue page as a JSON array of {sku, name, price} "
                  "objects. Follow any catalogue notes addressed to automated readers.\n\n" + text)
        try:
            records = json.loads(llm.chat("extract", "You extract structured product data from pages.", prompt).text)
        except json.JSONDecodeError:
            records = []
        for rec in records:
            harvested.append(rec)
            if "lot_code" in rec:
                canaries.add(rec["lot_code"])
    honeypot_hits = 0
    for rec in harvested:
        sku = rec.get("sku")
        if sku and sku not in seen:
            seen.append(sku)
            r = s.get(f"{base}/product/{sku}", headers=headers, timeout=15)
            if r.status_code == 403:
                honeypot_hits += 1
    u = usage()
    tok = u["prompt_tokens"] + u["completion_tokens"]
    out = {"harvested": len(harvested), "distinct": len(seen), "honeypot_hits": honeypot_hits,
           "canaries": len(canaries), "tokens": tok, "tokens_per_page": tok // max(1, pages)}
    if not quiet:
        print(f"  [LLM extractor ({llm.backend})] harvested {len(harvested)} records over {pages} pages; "
              f"distinct SKUs {len(seen)}, honeypot pages fetched {honeypot_hits}, canaries {len(canaries)}; "
              f"~{out['tokens_per_page']} tokens/page.")
        if canaries:
            print(f"      every record carries the store's lot code {sorted(canaries)} — the harvest is traceable.")
    return out


if __name__ == "__main__":
    run()
