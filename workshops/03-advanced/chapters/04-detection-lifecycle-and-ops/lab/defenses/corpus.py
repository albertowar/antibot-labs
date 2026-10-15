"""
The data the sensors depend on, with a date on it

data/ops_world.json is the edge's snapshot of the internet and of the browsers, built in lab
week 0: the JA4 table, an old community-blocklist entry, `built_week`. Three sensors lean on it
(and on the store's own feeds): the network feeds (netinfo.py), the header-order corpus
(sensor_headers.py) and the JA4 table (sensor_tls.py). The world keeps moving after the
snapshot; this module layers ../data/world_updates.json on top, which tools/refresh_corpus.py
writes when an operator runs the refresh:

    {"refreshed_week": {"asn_database": 3, "header_order": 3, "ja4_table": 3},
     "reassigned": {"203.0.113.0/27": "home_fiber"},     ranges that changed owner
     "header_order": {"chrome": [[...new order...]]},
     "ja4": {"chrome-146": "t13d..."}}

Hot-reloaded on mtime like everything else here. In production this is the nightly job that pulls
the new GeoIP/ASN database, the TLS corpus and the browser release notes, and the freshness
gauge that pages you when it has not run (tools/drift.corpus_ages, the corpus_age_weeks metric).
"""

import json
import os

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SNAPSHOT = os.path.join(LAB, "data", "ops_world.json")
UPDATES = os.path.join(LAB, "data", "world_updates.json")
_cache = {"mtime": None, "data": {}}
_snapshot = {}


def snapshot():
    """The week-0 snapshot (data/ops_world.json)."""
    if not _snapshot:
        with open(SNAPSHOT) as f:
            _snapshot.update(json.load(f))
    return _snapshot


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
        json.dump(data, f, indent=2, sort_keys=True)
    _cache["mtime"] = None


def clear():
    if os.path.exists(UPDATES):
        os.remove(UPDATES)
    _cache.update(mtime=None, data={})
