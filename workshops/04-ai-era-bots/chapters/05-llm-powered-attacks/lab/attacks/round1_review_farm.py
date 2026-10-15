"""Round 1 attack: an LLM review farm.

The old way (`--scripted`) is a template with slots: "Great {name}! The quality is amazing...". Forty of
those share a shingle pattern, so the store's content heuristics (duplicate and template detection) hold
them. The LLM way (default) asks the model for a fresh review per (persona, sentiment, length) combination.
Every review is unique, on-topic and types like a person, so content analysis has nothing left to grab.

The catch, which the student wires next, is that the farm still cannot buy 40 products or age 40 accounts.
It registers forty accounts this morning, spreads them over three devices on one datacenter's addresses,
and posts one review from each.

    python attacks/round1_review_farm.py                # LLM farm (beats the content heuristics)
    python attacks/round1_review_farm.py --scripted     # the old templated farm (held already)

Targets the local store only. Accounts and devices are synthetic.
"""

import argparse
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import FARM_POOL, JSON_HEADERS, bot, catalogue, finish  # noqa: E402
from llm import LLM  # noqa: E402  (tools/llm.py: the mock, or a model on this machine)

PERSONAS = ["weekend hiker", "busy parent", "gym regular", "daily commuter",
            "frequent traveller", "first-time buyer", "gift shopper", "value hunter"]
SENTIMENTS = ["positive", "positive", "positive", "mixed"]      # mostly glowing
LENGTHS = ["short", "medium", "medium", "long"]
_TEMPLATE = ("Great {name}! The quality is amazing and it arrived fast. "
             "Highly recommend it to everyone. Five stars!")


def review_text(llm, i, name, scripted=False):
    """One review for product `name`: the old template, or a fresh model-written one."""
    if scripted:
        return _TEMPLATE.format(name=name)
    prompt = (f"Write a customer product review.\nProduct: {name}\n"
              f"Persona: {PERSONAS[i % len(PERSONAS)]}\nSentiment: {SENTIMENTS[i % len(SENTIMENTS)]}\n"
              f"Length: {LENGTHS[i % len(LENGTHS)]}\nSeed: {i}\n"
              f"Write only the review text, first person, no title.")
    return llm.chat("review", "You write short, authentic-sounding product reviews.", prompt).text


def run(scripted=False, n=40, n_devices=3):
    llm = LLM()
    products = catalogue(n)
    seen = Counter()
    for i, (sku, name) in enumerate(products):
        text = review_text(llm, i, name, scripted)
        dev = i % n_devices
        c = bot(f"bot:farm:{i:02d}", FARM_POOL[dev], device=f"farm-device-{dev}")
        r = c.post("/api/register", json={"email": f"shopper_{i:04d}@mail.example", "password": f"Farm-pass-{i:04d}",
                                          "name": "Pat Reviewer"}, headers=JSON_HEADERS)
        if r.status_code != 201:
            seen["register_failed"] += 1
            continue
        r = c.post("/api/reviews", json={"sku": sku, "rating": 5, "title": "Great", "body": text}, headers=JSON_HEADERS)
        seen[{201: "published", 202: "held"}.get(r.status_code, "blocked")] += 1
    style = "scripted template" if scripted else "LLM-generated"
    print(f"[round1] {style} farm: {len(products)} accounts, {seen['published']} reviews published, "
          f"{seen['held']} held for moderation, {seen['blocked']} refused.")
    return finish({"attempted": len(products), "succeeded": seen["published"], "held": seen["held"],
                   "blocked": seen["blocked"], "register_failed": seen["register_failed"]})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scripted", action="store_true", help="old templated farm (held already)")
    a = ap.parse_args()
    run(scripted=a.scripted)
