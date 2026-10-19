"""
Round 1 reference: rules over the audit log.

Five rules, each one a sentence an analyst could defend in a review meeting:

  R1  impossible travel: two logins from different countries, too far apart for the
      time between them, the second on a device the account has never used, and a
      high-risk change within two hours. (The new-device clause is what keeps the
      geo-IP glitch cohort out: their country jumps, their device does not.)
  R2  new context + high-risk change: a login from a device AND a network the
      account has never used, followed within an hour by a high-risk change made by
      the user (not by support or a batch job). Travellers, password-manager
      migrants and email migrants all change things from known devices.
  R3  stuffed then entered: a bad-password failure from datacenter or hosting space
      in the prior 48 hours, then a password login from datacenter space. No
      sensitive action required: this is what catches access-only takeovers.

Every "new device / new network" clause below means new *relative to a history the
log actually contains*: the account must have at least ten earlier
events in the log. The log starts on 1 October; on an account's first day in it, everything
is new, and that is not a signal. (This is the left-censoring trap: without this
clause the same rules flag every email migrant and dormant returner whose first
appearance in the window is the change itself.)
  R4  MFA fatigue: five or more push failures inside fifteen minutes, then a success.
  R5  reset from nowhere: a user-initiated password reset requested from a device and
      country the account has never used, completed, and followed by a high-risk
      change within the hour. Forgetful owners reset from their own devices.

What it costs: every rule has a cohort on the other end, and the scorer prints it.
Widening R2 to medium-risk events (address, payment method, order) reaches part of
the phishing kit's victims, and blows the budget on new-phone upgraders and gift
buyers. Try it: python solutions/round1_rules.py --wide

Run:
    python solutions/round1_rules.py                     # writes solutions/checkpoints/suspects_r1.csv and scores it
    python solutions/round1_rules.py --out my_r1.csv
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from atolab import HIGH_RISK, MEDIUM_RISK, dedupe, first_seen, haversine_km, load_events, save_suspects, score_now, with_geo  # noqa: E402

STRICT_HIGH = ["password_change", "email_change_confirmed", "mfa_disabled", "recovery_email_change", "phone_change"]


def alerts_off(df):
    return (df["event_type"] == "notification_settings_changed") & (df["d_alerts_enabled"] == False)  # noqa: E712


def high_risk_user(df, wide=False):
    base = df["event_type"].isin(STRICT_HIGH) | alerts_off(df)
    if wide:
        base = base | df["event_type"].isin(MEDIUM_RISK)
    return base & (df["actor"] == "user")


def followed_within(df, trigger_mask, target_mask, hours):
    """event_ids of trigger rows that have a target row on the same account within `hours`."""
    trig = df.loc[trigger_mask, ["account_id", "ts", "event_id"]]
    targ = df.loc[target_mask, ["account_id", "ts"]].rename(columns={"ts": "t_ts"})
    m = trig.merge(targ, on="account_id")
    m = m[(m["t_ts"] >= m["ts"]) & (m["t_ts"] <= m["ts"] + pd.Timedelta(hours=hours))]
    return m.drop_duplicates("event_id")[["account_id", "event_id"]]


MIN_HISTORY = 10


def rule_impossible_travel(df, hr):
    logins = df[(df["event_type"] == "login_success") & (df["n_prior"] >= MIN_HISTORY)].copy()
    logins = with_geo(logins)
    logins = logins.sort_values(["account_id", "ts"])
    g = logins.groupby("account_id", observed=True)
    logins["p_country"] = g["country"].shift()
    logins["p_lat"] = g["lat"].shift()
    logins["p_lon"] = g["lon"].shift()
    logins["p_ts"] = g["ts"].shift()
    logins["km"] = haversine_km(logins["p_lat"], logins["p_lon"], logins["lat"], logins["lon"])
    hours = (logins["ts"] - logins["p_ts"]).dt.total_seconds() / 3600
    logins["kmh"] = logins["km"] / hours.clip(lower=1 / 60)
    cand = logins[(logins["country"].astype(str) != logins["p_country"].astype(str)) & (logins["km"] > 500) & (logins["kmh"] > 900) & logins["is_new_device_id"]]
    hits = followed_within(df, df["event_id"].isin(cand["event_id"]), hr, 2)
    return hits.assign(rule="R1_impossible_travel")


def rule_new_context_high_risk(df, hr):
    trig = (df["event_type"] == "login_success") & df["is_new_device_id"] & df["is_new_asn"] & (df["n_prior"] >= MIN_HISTORY)
    return followed_within(df, trig, hr, 1).assign(rule="R2_new_context_high_risk")


def rule_stuffed_then_entered(df):
    dc = df["asn_type"].isin(["datacenter"])
    fails = df[(df["event_type"] == "login_failure") & dc][["account_id", "ts"]].rename(columns={"ts": "f_ts"})
    logins = df[(df["event_type"] == "login_success") & dc & (df["auth_method"] == "password")][["account_id", "ts", "event_id"]]
    m = logins.merge(fails, on="account_id")
    m = m[(m["f_ts"] < m["ts"]) & (m["f_ts"] >= m["ts"] - pd.Timedelta(hours=48))]
    n = m.groupby("event_id").size()
    hit_ids = n[n >= 1].index
    return logins[logins["event_id"].isin(hit_ids)][["account_id", "event_id"]].assign(rule="R3_stuffed_then_entered")


def rule_mfa_fatigue(df):
    f = df[(df["event_type"] == "mfa_challenge_failure") & (df["mfa_method"] == "push")].sort_values(["account_id", "ts"])
    rows = []
    for acc, grp in f.groupby("account_id", observed=True):
        ts = grp["ts"].to_numpy()
        ids = grp["event_id"].to_numpy()
        j = 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > np.timedelta64(15, "m"):
                j += 1
            if i - j + 1 >= 5:
                rows.append((acc, ids[j]))
                break
    out = pd.DataFrame(rows, columns=["account_id", "event_id"])
    succ = df[(df["event_type"] == "mfa_challenge_success")][["account_id"]].drop_duplicates()
    return out.merge(succ, on="account_id").assign(rule="R4_mfa_fatigue")


def rule_reset_from_nowhere(df, hr):
    req = (df["event_type"] == "password_reset_requested") & (df["actor"] == "user") & df["is_new_device_id"] & df["is_new_country"] & (df["n_prior"] >= MIN_HISTORY)
    done = df["event_type"] == "password_reset_completed"
    step1 = followed_within(df, req, done, 1)
    hits = followed_within(df, df["event_id"].isin(step1["event_id"]), hr, 1)
    return hits.assign(rule="R5_reset_from_nowhere")


def run(df, wide=False):
    df = first_seen(df)
    df["n_prior"] = df.groupby("account_id", observed=True).cumcount()
    hr = high_risk_user(df, wide=wide)
    parts = [rule_impossible_travel(df, hr), rule_new_context_high_risk(df, hr), rule_stuffed_then_entered(df), rule_mfa_fatigue(df), rule_reset_from_nowhere(df, hr)]
    hits = pd.concat(parts, ignore_index=True)
    hits = hits.merge(df[["event_id", "ts"]], on="event_id").sort_values("ts")
    per_rule = hits.groupby("rule")["account_id"].nunique()
    print("accounts flagged per rule:\n" + per_rule.to_string())
    first = hits.groupby("account_id", observed=True).agg(first_event_id=("event_id", "first"), n_rules=("rule", "nunique")).reset_index()
    first = first.sort_values(["n_rules", "account_id"], ascending=[False, True])
    return first


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(HERE, "checkpoints", "suspects_r1.csv"))
    ap.add_argument("--wide", action="store_true", help="count medium-risk events too (see the docstring)")
    ap.add_argument("--no-score", action="store_true")
    args = ap.parse_args()
    df = dedupe(load_events())
    first = run(df, wide=args.wide)
    save_suspects(first[["account_id"]], args.out, scores=first["n_rules"], first_event=first["first_event_id"])
    if not args.no_score:
        score_now(args.out)


if __name__ == "__main__":
    main()
