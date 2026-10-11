"""Round 1 attack — an LLM review farm.

The old way (``--scripted``) is a template with slots: "Great {product}! The
{feature} is {adj}." Forty of those share a shingle pattern, so the store's
content heuristics (duplicate + template detection) hold it to near zero.

The LLM way (default) asks the model for a fresh review per (persona, sentiment,
length) combination. Every review is unique, on-topic and types like a person,
so content analysis has nothing left to grab. The catch, which the student wires
next, is that the farm still cannot buy 40 products or age 40 accounts: it posts
from accounts registered this morning, on a handful of devices and IPs.

Targets the local store only. The accounts and devices are synthetic.

    python attacks/round1_review_farm.py                # LLM farm (beats content heuristics)
    python attacks/round1_review_farm.py --scripted     # old templated farm (beaten already)
"""

from __future__ import annotations

import argparse
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import BASE_URL, DATACENTER, headers, require_local  # noqa: E402
sys.path.insert(0, os.path.dirname(HERE))
import json  # noqa: E402
from tools.llm import LLM  # noqa: E402

PERSONAS = ["weekend hiker", "busy parent", "gym regular", "daily commuter",
            "frequent traveller", "first-time buyer", "gift shopper", "value hunter"]
SENTIMENTS = ["positive", "positive", "positive", "mixed"]   # mostly glowing
LENGTHS = ["short", "medium", "medium", "long"]
_TEMPLATE = ("Great {name}! The quality is amazing and it arrived fast. "
             "Highly recommend this {name} to everyone. Five stars!")


def _device(i, n_devices):
    return f"farm-fp-{i % n_devices}", DATACENTER[i % n_devices]


def run(base=BASE_URL, scripted=False, n_devices=3):
    require_local(base)
    with open(os.path.join(os.path.dirname(HERE), "data", "farm_accounts.json")) as fh:
        accounts = json.load(fh)
    llm = LLM()
    published = 0
    for i, acct in enumerate(accounts):
        name = f"product {acct['sku']}"
        if scripted:
            text = _TEMPLATE.format(name=name)
        else:
            persona = PERSONAS[i % len(PERSONAS)]
            prompt = (f"Write a customer product review.\nProduct: {name}\n"
                      f"Persona: {persona}\nSentiment: {SENTIMENTS[i % len(SENTIMENTS)]}\n"
                      f"Length: {LENGTHS[i % len(LENGTHS)]}\nSeed: {i}\n"
                      f"Write only the review text, first person, no title.")
            text = llm.chat("review", "You write short, authentic-sounding product reviews.", prompt).text
        fp, ip = _device(i, n_devices)
        r = requests.post(f"{base}/review",
                          json={"sku": acct["sku"], "rating": 5, "text": text},
                          headers=headers("bot", ip, fp=fp, user=acct["email"], round_=1),
                          timeout=10)
        if r.json().get("outcome") == "allow":
            published += 1
    style = "scripted template" if scripted else "LLM-generated"
    print(f"[round1] {style} farm: posted {len(accounts)} reviews, {published} published.")
    return published


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scripted", action="store_true", help="old templated farm (already beaten)")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(base=a.url, scripted=a.scripted)
