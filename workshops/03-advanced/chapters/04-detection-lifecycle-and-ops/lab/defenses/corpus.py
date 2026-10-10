"""
Chapter 4 (W3): The data the sensors depend on, with a date on it

world.json is the edge's snapshot of the internet and of the browsers, built
in lab week 0. Three sensors lean on it: the ASN database (net), the header
order corpus (headers) and the JA4 table (tls). The world keeps moving after
the snapshot; this module layers ../data/world_updates.json on top, which
tools/refresh_corpus.py writes when an operator runs the refresh:

    {"refreshed_week": {"asn_database": 3, "header_order": 3, "ja4_table": 3},
     "reassigned": {"203.0.113.0/26": "fiber"},         ranges that changed owner
     "header_order": {"chrome": [[...old...], [...new...]]},
     "ja4": {"chrome-146": "t13d..."}}

Hot-reloaded on mtime like everything else in this lab. In production this is
the nightly job that pulls the new GeoIP/ASN database, the TLS corpus and the
browser release notes, and the freshness gauge that pages you when it has not
run (drift.corpus_ages).
"""

import json
import os

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
UPDATES = os.path.join(LAB, "data", "world_updates.json")
_cache = {"mtime": None, "data": {}}


def updates():
    try:
        mtime = os.path.getmtime(UPDATES)
    except OSError:
        _cache.update(mtime=None, data={})
        return {}
    if mtime != _cache["mtime"]:
        with open(UPDATES) as f:
            _cache.update(mtime=mtime, data=json.load(f))
    return _cache["data"]


def write(data):
    os.makedirs(os.path.dirname(UPDATES), exist_ok=True)
    with open(UPDATES, "w") as f:
        json.dump(data, f, indent=2)
    _cache["mtime"] = None


def clear():
    if os.path.exists(UPDATES):
        os.remove(UPDATES)
    _cache.update(mtime=None, data={})
