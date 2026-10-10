"""
script_monitor.py — DEFENSE (Round 1): detect when a script changes.

A one-time inventory is a snapshot; a compromise is a change. This hashes every
script in the inventory and compares against a saved baseline, alerting on:
  NEW      a script URL that was not in the baseline
  CHANGED  a known URL whose SHA-256 no longer matches
  REMOVED  a baseline URL that is gone

Detection is not prevention: finding the skimmer here does not stop it exfil-
trating. That is why Rounds 2-4 add CSP, SRI and the runtime monitor. What this
buys you is time-to-detect, which is the metric PCI req 11.6.1 cares about.

Fix vs. the naive version: the baseline path is explicit, not derived by string
surgery on a filename.

Prereqs:  pip install httpx
Usage:
  python script_monitor.py --create-baseline      # from script_inventory.json
  python script_monitor.py                         # re-hash and diff
"""

import argparse
import hashlib
import json
import os

import httpx

HERE = os.path.dirname(__file__)
INVENTORY = os.path.join(HERE, "script_inventory.json")
BASELINE = os.path.join(HERE, "script_baseline.json")


def _urls(inventory: dict) -> list:
    seen, urls = set(), []
    for scripts in inventory.values():
        for s in scripts:
            if s["url"] not in seen:
                seen.add(s["url"])
                urls.append(s["url"])
    return urls


def hash_url(client: httpx.Client, url: str) -> str:
    try:
        resp = client.get(url, timeout=10, follow_redirects=True)
        resp.raise_for_status()
        return "sha256-" + hashlib.sha256(resp.content).hexdigest()
    except httpx.HTTPError as exc:
        return f"ERROR:{exc.__class__.__name__}"


def hash_all(urls: list) -> dict:
    with httpx.Client() as client:
        return {url: hash_url(client, url) for url in urls}


def create_baseline() -> int:
    with open(INVENTORY) as fh:
        inventory = json.load(fh)
    hashes = hash_all(_urls(inventory))
    with open(BASELINE, "w") as fh:
        json.dump(hashes, fh, indent=2)
    print(f"Baseline written to {BASELINE} ({len(hashes)} scripts).")
    return 0


def diff() -> int:
    if not os.path.exists(BASELINE):
        print("No baseline yet. Run: python script_monitor.py --create-baseline")
        return 1
    with open(BASELINE) as fh:
        baseline = json.load(fh)
    with open(INVENTORY) as fh:
        inventory = json.load(fh)

    current = hash_all(_urls(inventory))
    alerts = []
    for url, h in current.items():
        if url not in baseline:
            alerts.append(f"NEW      {url}")
        elif baseline[url] != h:
            alerts.append(f"CHANGED  {url}\n           was {baseline[url]}\n           now {h}")
    for url in baseline:
        if url not in current:
            alerts.append(f"REMOVED  {url}")

    if not alerts:
        print(f"OK — {len(current)} scripts match the baseline.")
        return 0
    print(f"⚠️  {len(alerts)} supply-chain alert(s):\n")
    for a in alerts:
        print("  " + a)
    return len(alerts)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--create-baseline", action="store_true")
    args = ap.parse_args()
    raise SystemExit(create_baseline() if args.create_baseline else min(diff(), 1))


if __name__ == "__main__":
    main()
