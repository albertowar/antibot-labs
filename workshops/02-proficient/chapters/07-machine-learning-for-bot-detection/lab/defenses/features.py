"""
Chapter 7 — Session features: ONE function for training and serving (Section 7.2)

`compute()` turns a session's raw events into a flat feature dict. The
demo site calls it at checkout (online), and `build_dataset()` calls it for
every historical checkout (offline). Same code, same inputs, same "as of"
time. That is the cheapest insurance against training/serving skew, the bug
where the model was trained on features computed one way and served on
features computed another.

Point-in-time correctness: every feature only uses events with
ts <= as_of. A cohort count that peeks at sessions *after* the checkout
leaks the future into training and inflates offline metrics.

Feature families
  request   server-side log: pacing, assets, navigation, header basics
  network   ASN type from the simulated edge (defenses/netinfo.py)
  client    fingerprint + behavior summary from the page collector
            (W2 Ch3 / W2 Ch4). Absent for clients that never run JS.
  consistency  do the client's claims agree with each other and the network?
  cohort    population counts in a sliding window (Round 2, see cohort.py)

LEAKY features are derived from the same events as the weak labels
(defenses/labels.py). They are logged for analysts but must never be
model inputs: see `python defenses/train.py --include-leaky`.
"""

import json
import os
import re
import statistics
import sys
from collections import defaultdict

import numpy as np
import pandas as pd
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(__file__))

import cohort  # noqa: E402
from netinfo import ASN_TYPES, lookup  # noqa: E402
from store import LAB_TIME_SCALE  # noqa: E402

HONEYPOT_PATHS = ("/specials-archive", "/api/v0/")
PRODUCT_PAGE = re.compile(r"^/product/\d+$")

REQUEST_FEATURES = [
    "n_pages", "asset_ratio", "gap_median_s", "gap_cv", "gap_min_s",
    "duration_s", "referer_ratio", "products_viewed", "cart_to_checkout_s",
    "ua_is_library", "no_accept_language", "sec_fetch_ratio",
]
NETWORK_FEATURES = ["asn_type"]
CLIENT_FEATURES = [
    "has_fp", "has_beh", "webdriver", "software_gpu",
    "mouse_moves", "mouse_straightness", "mouse_speed_cv", "clicks", "keys",
    "key_interval_cv", "touches", "scrolls", "first_input_s",
]
CONSISTENCY_FEATURES = [
    "ua_platform_mismatch", "gpu_platform_mismatch", "touch_platform_mismatch",
    "tz_ip_mismatch",
]
COHORT_FEATURES = cohort.COHORT_FEATURES
LEAKY_FEATURES = ["honeypot_hits", "logged_in"]

PER_SESSION_FEATURES = REQUEST_FEATURES + NETWORK_FEATURES + CLIENT_FEATURES + CONSISTENCY_FEATURES
CATEGORICAL = ["asn_type"]

# Feature set per model version (train.py --round N)
FEATURE_SETS = {
    1: PER_SESSION_FEATURES,
    2: PER_SESSION_FEATURES + COHORT_FEATURES,
}

# Coarse tz -> country table for the zones the simulators use
TZ_COUNTRY = {
    "Europe/Madrid": "ES", "America/New_York": "US", "America/Chicago": "US",
    "America/Los_Angeles": "US", "Europe/Berlin": "DE", "Europe/London": "GB",
    "Europe/Amsterdam": "NL", "Asia/Tokyo": "JP", "UTC": "??",
}


def _os_from_ua(ua):
    ua = ua or ""
    if "iPhone" in ua or "iPad" in ua:
        return "ios"
    if "Android" in ua:
        return "android"
    if "Windows" in ua:
        return "windows"
    if "Mac OS X" in ua or "Macintosh" in ua:
        return "mac"
    if "Linux" in ua:
        return "linux"
    return "other"


def _os_from_platform(platform):
    p = (platform or "").lower()
    if p.startswith("win"):
        return "windows"
    if p.startswith("mac"):
        return "mac"
    if p in ("iphone", "ipad"):
        return "ios"
    if "arm" in p or "aarch" in p:
        return "android"
    if p.startswith("linux"):
        return "linux"
    return "other"


def _cv(values):
    if len(values) < 2:
        return np.nan
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else np.nan


def fingerprint_consistency(fp, header_ua, ip_country):
    """Do the client's claims agree with each other and with the network?"""
    plat_os = _os_from_platform(fp.get("platform"))
    ua_os = _os_from_ua(header_ua)
    gpu = (fp.get("gpu") or "").lower()
    mobile = plat_os in ("ios", "android")
    apple_gpu = "apple" in gpu
    mobile_gpu = any(k in gpu for k in ("adreno", "mali", "powervr"))
    tz_cc = TZ_COUNTRY.get(fp.get("tz"), "??")
    return {
        "ua_platform_mismatch": int(plat_os != ua_os),
        "gpu_platform_mismatch": int((apple_gpu and plat_os not in ("mac", "ios"))
                                     or (mobile_gpu and not mobile)),
        "touch_platform_mismatch": int(mobile and int(fp.get("touch", 0)) == 0),
        # UTC is what privacy browsers report: unknown, not a mismatch
        "tz_ip_mismatch": int(tz_cc != "??" and tz_cc != ip_country),
        "software_gpu": int(any(k in gpu for k in ("swiftshader", "llvmpipe", "software"))),
    }


def compute(req, tel, logins, as_of, cohort_window=None):
    """
    Feature dict for ONE session. Plain Python on purpose: easy to read, and
    fast enough to run inline on every checkout.

    req       this session's requests: list of dicts (ts, method, path, ip, ua, ...)
    tel       this session's telemetry: list of dicts (ts, kind, payload, fp_hash, ip)
    logins    number of logins by this session
    as_of     only events with ts <= as_of are used
    cohort_window  cohort.Window with population rows, or None (no cohort features)
    """
    # The checkout POST is logged after it is scored: never part of its own features
    req = sorted((r for r in req if r["ts"] <= as_of and r["path"] != "/checkout"),
                 key=lambda r: r["ts"])
    tel = sorted((t for t in tel if t["ts"] <= as_of), key=lambda t: t["ts"])
    f = {}

    # --- request features -------------------------------------------------
    assets = [r for r in req if r["is_asset"]]
    actions = [r for r in req if not r["is_asset"] and not r["path"].startswith("/api/telemetry")]
    pages = [r for r in actions if r["method"] == "GET"]
    gaps = [(b["ts"] - a["ts"]) / LAB_TIME_SCALE for a, b in zip(actions, actions[1:])]
    f["n_pages"] = len(pages)
    f["asset_ratio"] = len(assets) / max(len(pages), 1)
    f["gap_median_s"] = statistics.median(gaps) if gaps else np.nan
    f["gap_cv"] = _cv(gaps)
    f["gap_min_s"] = min(gaps) if gaps else np.nan
    f["duration_s"] = (as_of - req[0]["ts"]) / LAB_TIME_SCALE if req else 0.0
    f["referer_ratio"] = (sum(bool(p["referer"]) for p in pages) / len(pages)) if pages else 0.0
    f["products_viewed"] = len({p["path"] for p in pages if PRODUCT_PAGE.match(p["path"])})
    cart = [r["ts"] for r in actions if r["path"] == "/cart/add"]
    f["cart_to_checkout_s"] = (as_of - max(cart)) / LAB_TIME_SCALE if cart else np.nan
    first = req[0] if req else {}
    ua = first.get("ua") or ""
    f["ua_is_library"] = int("Mozilla/" not in ua)
    f["no_accept_language"] = int(not first.get("accept_language"))
    f["sec_fetch_ratio"] = (sum(bool(p["sec_fetch_site"]) for p in pages) / len(pages)) if pages else 0.0

    # --- network ------------------------------------------------------------
    ip = first.get("ip") or ""
    net = lookup(ip)
    f["asn_type"] = ASN_TYPES.index(net["asn_type"])

    # --- client telemetry -------------------------------------------------
    fp_rows = [t for t in tel if t["kind"] == "fp"]
    beh_rows = [t for t in tel if t["kind"] == "beh"]
    fp = json.loads(fp_rows[-1]["payload"]) if fp_rows else None
    beh = json.loads(beh_rows[-1]["payload"]) if beh_rows else None
    f["has_fp"] = int(fp is not None)
    f["has_beh"] = int(beh is not None)
    f["webdriver"] = int(bool(fp and fp.get("webdriver")))
    for name, key in [("mouse_moves", "mouse_moves"), ("mouse_straightness", "straightness"),
                      ("mouse_speed_cv", "speed_cv"), ("clicks", "clicks"), ("keys", "keys"),
                      ("key_interval_cv", "key_cv"), ("touches", "touches"),
                      ("scrolls", "scrolls")]:
        f[name] = float(beh[key]) if beh and beh.get(key) is not None else np.nan
    f["first_input_s"] = beh["first_input_ms"] / 1000 if beh else np.nan
    # Not a model input: the device "shape" anomaly.py measures rarity on
    f["fp_combo"] = f"{fp.get('platform')}|{fp.get('gpu')}|{fp.get('screen')}" if fp else None

    # --- consistency ---------------------------------------------------------
    if fp is not None:
        f.update(fingerprint_consistency(fp, ua, net["country"]))
    else:
        f.update({k: np.nan for k in CONSISTENCY_FEATURES})
        f["software_gpu"] = np.nan

    # --- leaky (label-source) features: logged, never trained on --------------
    f["honeypot_hits"] = sum(r["path"].startswith(HONEYPOT_PATHS) for r in req)
    f["logged_in"] = int(logins > 0)

    # --- cohort features (Round 2) -------------------------------------------
    fp_hash = fp_rows[-1]["fp_hash"] if fp_rows else None
    f["fp_hash"] = fp_hash   # not a model input: for analysts and cluster labeling
    if cohort_window is not None:
        f.update(cohort.features(cohort_window, ip, fp_hash))
    return f


def _records(conn, sql):
    return [dict(r) for r in conn.execute(text(sql)).mappings()]


def build_dataset(conn, with_cohort=True):
    """
    One row per checkout attempt, features computed as of the checkout time.
    Columns: sid, ts, ip, account, <features>.
    """
    orders = _records(conn, "SELECT sid, ts FROM orders ORDER BY ts")
    if not orders:
        return pd.DataFrame()
    req_by, tel_by = defaultdict(list), defaultdict(list)
    for r in _records(conn, "SELECT * FROM requests"):
        req_by[r["sid"]].append(r)
    telemetry = _records(conn, "SELECT * FROM telemetry")
    for t in telemetry:
        tel_by[t["sid"]].append(t)
    login_by = {}
    for row in _records(conn, "SELECT sid, account FROM logins ORDER BY ts"):
        login_by.setdefault(row["sid"], row["account"])
    index = (cohort.PopulationIndex(_records(conn, "SELECT * FROM sessions"), telemetry)
             if with_cohort else None)

    rows, seen = [], set()
    for o in orders:
        if o["sid"] in seen:      # first checkout per session is the decision we model
            continue
        seen.add(o["sid"])
        req = req_by.get(o["sid"], [])
        window = index.window(o["ts"]) if index is not None else None
        f = compute(req, tel_by.get(o["sid"], []), int(o["sid"] in login_by), o["ts"], window)
        f.update({"sid": o["sid"], "ts": o["ts"], "account": login_by.get(o["sid"]),
                  "ip": req[0]["ip"] if req else ""})
        rows.append(f)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    from store import make_engine
    with make_engine().connect() as conn:
        df = build_dataset(conn)
    if df.empty:
        print("No checkouts yet. Run tools/simulate.py first.")
    else:
        pd.set_option("display.width", 200)
        print(f"{len(df)} checkout sessions, {len(df.columns)} columns")
        print(df[PER_SESSION_FEATURES + COHORT_FEATURES].describe().T.round(2))
