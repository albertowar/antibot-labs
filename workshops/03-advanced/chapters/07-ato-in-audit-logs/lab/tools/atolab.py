"""
Chapter 7 helper module: the plumbing, so the 30-minute rounds are spent on detection.

    from atolab import *
    df = load_events()                 # the whole 90-day log, sorted by ts then event_id
    timeline(df, "acc_001234")         # one account, with novelty flags relative to its own past
    S = sessionize(df)                 # one row per session: ASNs, JA4s, fingerprints seen
    G = build_bipartite(df, keys=("device_id", "fp_hash", "ja4"))
    P = project_accounts(G, min_weight=1.0)
    F = window_features(df, as_of="2026-11-30")   # leak-free per-account features
    save_suspects(ids, "suspects_r1.csv"); score_now("suspects_r1.csv")

Nothing here decides anything. The deliberate exception is load_events(): it does
NOT drop duplicate or retried lines, because noticing them is part of Round 0.
Call dedupe(df) once you have.
"""

import gzip
import json
import math
import os
import subprocess
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
DATA = os.path.join(LAB, "data", "account_activity.jsonl.gz")
WORLD = os.path.join(LAB, "data", "world.json")

HIGH_RISK = ["password_change", "email_change_confirmed", "mfa_disabled", "recovery_email_change", "notification_settings_changed", "phone_change",
             "password_reset_completed", "sessions_revoked_all", "passkey_added", "api_token_created", "mfa_backup_codes_regenerated"]
MEDIUM_RISK = ["address_added", "payment_method_added", "order_placed", "gift_card_purchased", "third_party_linked", "mfa_enabled"]
DETAIL_COLS = ["reason", "agent_id", "ticket_id", "channel", "provider", "provider_sub_hash", "parent_session_hash", "ship_to_new_address",
               "ship_country", "amount", "alerts_enabled", "old_domain", "new_domain", "retry", "batch", "identity_check", "signup_channel", "email_domain"]

__all__ = ["load_events", "dedupe", "timeline", "haversine_km", "with_geo", "sessionize", "first_seen", "build_bipartite", "project_accounts",
           "component_report", "window_features", "precision_at_k", "save_suspects", "score_now", "HIGH_RISK", "MEDIUM_RISK", "DATA", "pd", "np"]


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------

def load_events(path=None, nrows=None):
    """Read the gzipped JSONL (or a .jsonl / .csv) into a DataFrame.

    Parses ts and ingested_at as UTC datetimes, flattens the common details.*
    keys into d_* columns, sorts by (ts, event_id). Duplicates and retries are
    kept on purpose; see dedupe()."""
    path = path or DATA
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Generate it first: python tools/make_log.py")
    if path.endswith(".csv"):
        df = pd.read_csv(path, nrows=nrows)
        df["details"] = df["details"].apply(json.loads)
    else:
        opener = gzip.open if path.endswith(".gz") else open
        rows = []
        with opener(path, "rt") as f:
            for i, line in enumerate(f):
                if nrows is not None and i >= nrows:
                    break
                rows.append(json.loads(line))
        df = pd.DataFrame(rows)
    details = pd.DataFrame(list(df["details"]), index=df.index)
    for c in DETAIL_COLS:
        df["d_" + c] = details[c] if c in details.columns else np.nan
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["ingested_at"] = pd.to_datetime(df["ingested_at"], utc=True)
    for c in ("event_type", "outcome", "actor", "client", "asn_type", "country", "city", "ja4", "auth_method", "mfa_method", "accept_language"):
        df[c] = df[c].astype("category")
    df = df.sort_values(["ts", "event_id"], kind="mergesort").reset_index(drop=True)
    return df


def dedupe(df):
    """Drop exact duplicate lines (same event_id) and client retries (same request_id).
    Keeps the first copy by ts. Returns a new frame and prints what it removed."""
    n0 = len(df)
    out = df.drop_duplicates("event_id", keep="first")
    n1 = len(out)
    out = out.drop_duplicates("request_id", keep="first").reset_index(drop=True)
    print(f"dedupe: {n0 - n1} duplicate lines, {n1 - len(out)} retries removed, {len(out)} events left")
    return out


# ----------------------------------------------------------------------------
# Looking at one account
# ----------------------------------------------------------------------------

def first_seen(df, cols=("device_id", "fp_hash", "ja4", "asn", "country", "ip")):
    """Add is_new_<col>: True the first time this account is seen with that value,
    in time order, with no lookahead. Rows must be sorted by ts."""
    out = df
    for c in cols:
        key = out["account_id"].astype(str) + "|" + out[c].astype(str)
        out["is_new_" + c] = ~key.duplicated()
    return out


def timeline(df, account_id, around=None, n=60, cols=None):
    """Print one account's events with the gap to the previous event and novelty flags."""
    a = df[df["account_id"] == account_id].sort_values(["ts", "event_id"]).copy()
    if a.empty:
        print(f"{account_id}: no events")
        return a
    a = first_seen(a)
    a["gap"] = a["ts"].diff().apply(lambda d: "" if pd.isna(d) else _fmt_gap(d))
    flags = []
    for _, r in a.iterrows():
        f = []
        if r["is_new_device_id"]:
            f.append("NEW-DEV")
        if r["is_new_country"]:
            f.append("NEW-CTRY")
        if r["is_new_asn"]:
            f.append("NEW-ASN")
        if r["is_new_ja4"]:
            f.append("NEW-JA4")
        flags.append(" ".join(f))
    a["flags"] = flags
    cols = cols or ["event_id", "ts", "gap", "event_type", "outcome", "actor", "auth_method", "country", "city", "asn_type", "device_id", "ja4", "flags"]
    if around is not None:
        idx = a.index[a["event_id"] == around]
        if len(idx):
            pos = a.index.get_loc(idx[0])
            a = a.iloc[max(0, pos - n // 2): pos + n // 2]
    else:
        a = a.tail(n)
    with pd.option_context("display.max_rows", 500, "display.width", 250, "display.max_colwidth", 28):
        print(a[cols].to_string(index=False))
    return a


def _fmt_gap(d):
    s = d.total_seconds()
    if s < 90:
        return f"+{s:.0f}s"
    if s < 5400:
        return f"+{s / 60:.0f}m"
    if s < 172800:
        return f"+{s / 3600:.1f}h"
    return f"+{s / 86400:.1f}d"


# ----------------------------------------------------------------------------
# Geography
# ----------------------------------------------------------------------------

def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance, vectorised over numpy arrays or pandas Series."""
    lat1, lon1, lat2, lon2 = map(np.radians, (np.asarray(lat1, float), np.asarray(lon1, float), np.asarray(lat2, float), np.asarray(lon2, float)))
    a = np.sin((lat2 - lat1) / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * np.arcsin(np.sqrt(a))


def with_geo(df, world_path=None):
    """Join city centroids (lat, lon) from data/world.json onto (country, city)."""
    with open(world_path or WORLD) as f:
        cities = pd.DataFrame(json.load(f)["cities"])[["country", "city", "lat", "lon"]]
    out = df.copy()
    out["country"] = out["country"].astype(str)
    out["city"] = out["city"].astype(str)
    return out.merge(cities, on=["country", "city"], how="left")


# ----------------------------------------------------------------------------
# Sessions
# ----------------------------------------------------------------------------

def sessionize(df):
    """One row per (account, session_id): time span, counts and the distinct
    networks and stacks seen inside it. parent_session_hash links a rotated
    session to the one it resumed from (only some clients report it)."""
    g = df.groupby(["account_id", "session_id"], observed=True)
    S = g.agg(start=("ts", "min"), end=("ts", "max"), n_events=("event_id", "count"), n_ip=("ip", "nunique"), n_asn=("asn", "nunique"),
              n_country=("country", "nunique"), n_ja4=("ja4", "nunique"), n_fp=("fp_hash", "nunique"), n_device=("device_id", "nunique"),
              auth=("auth_method", lambda s: next((x for x in s if isinstance(x, str)), None)),
              parent=("d_parent_session_hash", lambda s: next((x for x in s if isinstance(x, str)), None))).reset_index()
    S["duration_min"] = (S["end"] - S["start"]).dt.total_seconds() / 60
    return S


# ----------------------------------------------------------------------------
# Graphs
# ----------------------------------------------------------------------------

def build_bipartite(df, keys=("device_id", "fp_hash", "ja4"), weights=None, idf=True, since=None, until=None, min_accounts=2, max_accounts=None, event_types=None):
    """Account <-> identifier bipartite graph.

    Nodes: "acc:<account_id>" and "<key>:<value>". An edge means the account was
    seen with that identifier; attrs: first_seen, last_seen, n_events, weight.
    weight = base weight for the key type (default 1.0) times, with idf=True,
    log(N_accounts / accounts_sharing_value), so a value shared by everyone
    (a top JA4, a carrier egress IP) weighs almost nothing. Values seen on fewer
    than min_accounts accounts are dropped (they cannot link anything)."""
    import networkx as nx
    weights = weights or {}
    d = df
    if since is not None:
        d = d[d["ts"] >= pd.Timestamp(since, tz="UTC")]
    if until is not None:
        d = d[d["ts"] < pd.Timestamp(until, tz="UTC")]
    if event_types is not None:
        d = d[d["event_type"].isin(event_types)]
    n_acc = d["account_id"].nunique()
    G = nx.Graph()
    for key in keys:
        sub = d[["account_id", key, "ts"]].dropna()
        sub = sub[sub[key].astype(str) != ""]
        agg = sub.groupby(["account_id", key], observed=True).agg(first_seen=("ts", "min"), last_seen=("ts", "max"), n_events=("ts", "count")).reset_index()
        share = agg.groupby(key, observed=True)["account_id"].nunique()
        ok = share[share >= min_accounts]
        if max_accounts is not None:
            ok = ok[ok <= max_accounts]
        agg = agg[agg[key].isin(ok.index)]
        base = float(weights.get(key, 1.0))
        for r in agg.itertuples(index=False):
            val = getattr(r, key)
            w = base * (math.log(n_acc / share[val]) if idf else 1.0)
            G.add_node(f"acc:{r.account_id}", kind="account")
            G.add_node(f"{key}:{val}", kind=key, n_accounts=int(share[val]))
            G.add_edge(f"acc:{r.account_id}", f"{key}:{val}", weight=w, first_seen=r.first_seen, last_seen=r.last_seen, n_events=int(r.n_events))
    return G


def project_accounts(G, min_weight=0.0):
    """Account-account projection: two accounts are linked if they share an identifier;
    the edge weight sums the identifier weights, and 'via' lists the identifier kinds."""
    import networkx as nx
    P = nx.Graph()
    for node, data in G.nodes(data=True):
        if data.get("kind") == "account":
            continue
        accs = list(G.neighbors(node))
        if len(accs) < 2:
            continue
        kind = data.get("kind")
        for i in range(len(accs)):
            for j in range(i + 1, len(accs)):
                w = min(G[accs[i]][node]["weight"], G[accs[j]][node]["weight"])
                if P.has_edge(accs[i], accs[j]):
                    P[accs[i]][accs[j]]["weight"] += w
                    P[accs[i]][accs[j]]["via"].add(kind)
                else:
                    P.add_edge(accs[i], accs[j], weight=w, via={kind})
    drop = [(u, v) for u, v, w in P.edges(data="weight") if w < min_weight]
    P.remove_edges_from(drop)
    P.remove_nodes_from([n for n in list(P.nodes) if P.degree(n) == 0])
    return P


def component_report(P, df=None, top=25):
    """Connected components of an account projection, largest first, with the
    identifier kinds that hold them together and (if df given) the time span
    over which the component's accounts were first touched by the shared ids."""
    import networkx as nx
    rows = []
    for comp in nx.connected_components(P):
        accs = sorted(a.split(":", 1)[1] for a in comp)
        via = set()
        wsum = 0.0
        for u, v, d in P.subgraph(comp).edges(data=True):
            via |= d["via"]
            wsum += d["weight"]
        rows.append({"size": len(accs), "weight": round(wsum, 2), "via": "+".join(sorted(via)), "accounts": accs})
    R = pd.DataFrame(rows).sort_values(["size", "weight"], ascending=False).reset_index(drop=True)
    return R.head(top) if top else R


# ----------------------------------------------------------------------------
# Features for models
# ----------------------------------------------------------------------------

def window_features(df, as_of=None, windows=(1, 7, 30), baseline_days=60):
    """Per-account feature table using only events with ts < as_of (no leakage).

    Two groups: recent-window counts (logins, failures, high/medium-risk events,
    distinct countries/ASNs/devices/JA4s, new-identifier events) for each window,
    and deltas against the account's own earlier behaviour (hour-of-day distance
    from its usual hour, share of events from its modal country/ASN/device,
    order amount vs its median). Accounts with fewer than ~8 baseline events get
    NaN deltas: there is nothing to compare against, and a model should know."""
    as_of = pd.Timestamp(as_of, tz="UTC") if as_of is not None else df["ts"].max() + pd.Timedelta(seconds=1)
    d = df[df["ts"] < as_of].copy()
    d = first_seen(d)
    d["hour"] = ((d["ts"] + pd.to_timedelta(d["tz_offset"].fillna(0).astype(int), unit="m")).dt.hour).astype(float)
    d["is_login"] = d["event_type"] == "login_success"
    d["is_fail"] = d["event_type"] == "login_failure"
    user = d["actor"] == "user"            # the policy engine and support batches act on accounts too; they are not the account
    d["is_high"] = d["event_type"].isin(HIGH_RISK) & user
    d["is_med"] = d["event_type"].isin(MEDIUM_RISK) & user
    d["is_resume"] = d["auth_method"] == "session_resume"
    d["is_new_any"] = d[["is_new_device_id", "is_new_asn", "is_new_country", "is_new_ja4"]].any(axis=1)
    d["amount"] = pd.to_numeric(d["d_amount"], errors="coerce")
    d["alerts_off"] = (d["event_type"] == "notification_settings_changed") & (d["d_alerts_enabled"] == False)  # noqa: E712
    # A failed attempt from an unknown device at 03:00 from another continent is the attacker *not*
    # getting in. It must not move the account's hour, country, network or novelty features, so every
    # behavioural feature below is computed from successful events; failures are only ever counted.
    succ = d[d["outcome"] == "success"]
    feats = []
    base_cut = as_of - pd.Timedelta(days=max(windows))
    base = succ[succ["ts"] < base_cut]
    gb = base.groupby("account_id", observed=True)
    base_n = gb.size().rename("base_events")
    base_hour = gb["hour"].agg(lambda s: _circular_mean(s)).rename("base_hour")
    base_country = gb["country"].agg(_mode).rename("base_country")
    base_asn = gb["asn"].agg(_mode).rename("base_asn")
    base_dev = gb["device_id"].agg(_mode).rename("base_device")
    base_amount = gb["amount"].median().rename("base_amount")
    base_tz = gb["tz_offset"].agg(_mode).rename("base_tz")
    base_lang = gb["accept_language"].agg(_mode).rename("base_lang")
    last_ts = gb["ts"].max().rename("base_last_ts")
    B = pd.concat([base_n, base_hour, base_country, base_asn, base_dev, base_amount, base_tz, base_lang, last_ts], axis=1)
    for wdays in windows:
        cut = as_of - pd.Timedelta(days=wdays)
        r_all = d[d["ts"] >= cut]
        r = succ[succ["ts"] >= cut]
        g_all = r_all.groupby("account_id", observed=True)
        g = r.groupby("account_id", observed=True)
        F = pd.DataFrame({
            f"w{wdays}_events": g_all.size(), f"w{wdays}_logins": g["is_login"].sum(), f"w{wdays}_fails": g_all["is_fail"].sum(),
            f"w{wdays}_high": g["is_high"].sum(), f"w{wdays}_med": g["is_med"].sum(), f"w{wdays}_resume_share": g["is_resume"].mean(),
            f"w{wdays}_countries": g["country"].nunique(), f"w{wdays}_asns": g["asn"].nunique(), f"w{wdays}_devices": g["device_id"].nunique(),
            f"w{wdays}_ja4s": g["ja4"].nunique(), f"w{wdays}_new_ids": g["is_new_any"].sum(), f"w{wdays}_alerts_off": g["alerts_off"].sum(),
            f"w{wdays}_max_amount": g["amount"].max(), f"w{wdays}_hour_mean": g["hour"].agg(_circular_mean),
        })
        rj = r.join(B, on="account_id")
        F[f"w{wdays}_share_base_country"] = (rj["country"].astype(str) == rj["base_country"].astype(str)).groupby(rj["account_id"], observed=True).mean()
        F[f"w{wdays}_share_base_asn"] = (rj["asn"] == rj["base_asn"]).groupby(rj["account_id"], observed=True).mean()
        F[f"w{wdays}_share_base_device"] = (rj["device_id"] == rj["base_device"]).groupby(rj["account_id"], observed=True).mean()
        F[f"w{wdays}_tz_shift"] = (rj["tz_offset"] != rj["base_tz"]).groupby(rj["account_id"], observed=True).mean()
        F[f"w{wdays}_lang_shift"] = (rj["accept_language"].astype(str) != rj["base_lang"].astype(str)).groupby(rj["account_id"], observed=True).mean()
        feats.append(F)
    X = pd.concat(feats, axis=1).join(B, how="left")
    X["hour_delta"] = _circular_delta(X[f"w{max(windows)}_hour_mean"], X["base_hour"])
    X["amount_ratio"] = X[f"w{max(windows)}_max_amount"] / X["base_amount"]
    X["days_since_base"] = (as_of - X["base_last_ts"]).dt.total_seconds() / 86400
    thin = X["base_events"].fillna(0) < 8
    for c in ("hour_delta", "amount_ratio"):
        X.loc[thin, c] = np.nan
    X = X.drop(columns=["base_country", "base_asn", "base_device", "base_tz", "base_lang", "base_last_ts"])
    return X.fillna({c: 0 for c in X.columns if c.startswith("w")})


def _mode(s):
    m = s.dropna().mode()
    return m.iat[0] if len(m) else None


def _circular_mean(hours):
    h = np.asarray(hours, float)
    h = h[~np.isnan(h)]
    if len(h) == 0:
        return np.nan
    ang = h / 24 * 2 * np.pi
    return (math.atan2(np.sin(ang).mean(), np.cos(ang).mean()) % (2 * np.pi)) / (2 * np.pi) * 24


def _circular_delta(a, b):
    d = (a - b).abs() % 24
    return d.where(d <= 12, 24 - d)


# ----------------------------------------------------------------------------
# Scoring glue
# ----------------------------------------------------------------------------

def precision_at_k(ranked_ids, truth, k):
    ranked = list(ranked_ids)[:k]
    if not ranked:
        return 0.0
    return sum(1 for x in ranked if x in truth) / len(ranked)


def save_suspects(ids, path, scores=None, first_event=None):
    """Write the scorer's input: account_id[, score][, first_event_id]. Order matters
    when there is no score column (file order is the rank)."""
    if isinstance(ids, pd.DataFrame):
        out = ids.copy()
        if "account_id" not in out.columns:
            raise ValueError("DataFrame needs an account_id column")
    else:
        out = pd.DataFrame({"account_id": list(ids)})
    if scores is not None:
        out["score"] = list(scores)
    if first_event is not None:
        out["first_event_id"] = list(first_event)
    out = out.drop_duplicates("account_id")
    out.to_csv(path, index=False)
    print(f"wrote {len(out)} suspects to {path}")
    return path


def score_now(path, *args):
    """Run tools/score.py on a suspects file and print its report."""
    cmd = [sys.executable, os.path.join(HERE, "score.py"), path, *args]
    subprocess.run(cmd, check=False)
