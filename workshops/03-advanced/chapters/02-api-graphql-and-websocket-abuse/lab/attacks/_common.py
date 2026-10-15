"""
Shared attacker helpers for Chapter 2 (rules of engagement built in).

Every attack script imports this module, and through it tools/labclient.py, which runs the labnet guard (the
target must be this machine) and rents source addresses from data/world.json: documentation ranges, never a
real proxy, never a public proxy list. Accounts, tokens and data are synthetic.

Every attack ends by printing the one JSON line tools/checkpoint.py reads:

    attempted / succeeded     what the attacker set out to get / what it actually got
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "..", "tools"), os.path.join(HERE, "..")]

from api_sdk import APP_UA, DROP_SKU, SCRIPT_UA, ApiApp, bid, open_feed  # noqa: E402,F401
from labclient import BASE_URL, world_pool  # noqa: E402,F401


def bot_ip(i=0):
    """A datacenter address from the cloud_vm pool: where a scraper really runs from."""
    return world_pool("cloud_vm")[i]


def finish(name, attempted, succeeded, label, **extra):
    s = {"attack": name, "attempted": attempted, "succeeded": succeeded, **extra}
    print(f"=== {name}: {succeeded}/{attempted} {label} ===")
    print(json.dumps(s))
    return s
