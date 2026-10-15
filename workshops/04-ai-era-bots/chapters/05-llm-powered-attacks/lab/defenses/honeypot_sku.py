"""
Round 3, pre-wired: a request for a SKU that no person was ever shown.

The four honeypot products live in `data/honeypots.json`, not in the catalogue: no listing, sitemap or
search result links to them, and a browser cannot reach them by following the page. The only way to learn
a honeypot SKU is to read text a person never sees, which is what Round 3's `extractor_traps.py` plants.
A client that then asks for the product page has identified itself as a machine reader (W1 Ch8).

It is a hard block (score 100), the way a trap hit is in the W1 ladder. It sits in LADDER[0] because the
store already had it; Round 3's traps are the missing half that make a text-only extractor walk into it.
"""

import json
import os
import re

from .pipeline import Check, Signal, Verdict

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "honeypots.json")
_PRODUCT = re.compile(r"^/(?:api/)?products?/([^/]+)$")
_cache = []


def honeypots():
    """[{"sku", "name", "price"}, ...]"""
    if not _cache:
        with open(PATH) as f:
            _cache.extend(json.load(f))
    return _cache


def skus():
    return {h["sku"] for h in honeypots()}


def _check(ctx):
    m = _PRODUCT.match(ctx.path)
    if m and m.group(1) in skus():
        return Verdict("block", signals=(Signal("honeypot", "hidden_sku", 100, m.group(1)),))
    return None


CHECK = Check("honeypot", _check, phases=("request",))
