"""
Chapter 2 — How Many Real People Share This Fingerprint? (Section 2.5, Round 3)

(Rarity weighting. `python -m defenses.rarity` prints the classes.)

A fingerprint is only an identifier if few people share it. Eight people
on the same iPhone model, or a whole office on the same laptop image,
present the same fingerprint, and that is normal. Before we treat "five
accounts from one fingerprint" as abuse, we ask how many real visitors
would share it anyway.

We estimate that from `population_sample.json`: the share of last month's
visitors in each device class (OS | GPU | screen | cores). In production
you'd compute this table nightly from your own traffic (excluding traffic
you already blocked). The numbers shipped with the lab are illustrative,
for a store with 2 million monthly visitors.

    expected sharers < 1,000      rare device       → at most 3 accounts per fingerprint per day
    expected sharers < 50,000     uncommon device   → at most 10
    otherwise                     common device     → don't link on the fingerprint alone

A class we have never seen counts as rare. That is the right default for
an attacker's spoofed or harvested device, and a cheap one for a real
user: they only ever create one account.

Trade-off: the table goes stale (a new iPhone ships every September), and
attackers who read this file will replay a *common* fingerprint. That is
exactly the hand-off to the next layers (TLS in W2 Ch3, ML in W2 Ch7).
"""

import json
import os

SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "population_sample.json")
RARE_SHARERS = 1_000
UNCOMMON_SHARERS = 50_000
RARE_LIMIT = 3
UNCOMMON_LIMIT = 10

with open(SAMPLE_PATH) as f:
    _SAMPLE = json.load(f)
MONTHLY_VISITORS = _SAMPLE["monthly_visitors"]
CLASS_SHARE = _SAMPLE["device_classes"]


def expected_sharers(device_class):
    """Estimated number of real monthly visitors with this device class."""
    return round(CLASS_SHARE.get(device_class, 0.0) * MONTHLY_VISITORS)


def account_limit(device_class, mode="rarity"):
    """
    Maximum accounts per fingerprint per day, or None for "don't link".

    mode="naive" treats every fingerprint as unique: the version learners
    run first in Round 3 to see who it hurts.
    """
    if mode == "naive":
        return RARE_LIMIT
    sharers = expected_sharers(device_class)
    if sharers < RARE_SHARERS:
        return RARE_LIMIT
    if sharers < UNCOMMON_SHARERS:
        return UNCOMMON_LIMIT
    return None


if __name__ == '__main__':
    for cls in ["iOS|Apple GPU|390x844@3|4",
                "Windows|Intel(R) UHD Graphics 620|1920x1080@1|8",
                "macOS|Apple M2|1470x956@2|8",
                "Windows|NVIDIA GeForce RTX 3060|2560x1440@1|16",
                "Linux|SwiftShader|1280x720@1|12"]:
        print(f"{cls:<52} sharers≈{expected_sharers(cls):>9,}  limit={account_limit(cls)}")
