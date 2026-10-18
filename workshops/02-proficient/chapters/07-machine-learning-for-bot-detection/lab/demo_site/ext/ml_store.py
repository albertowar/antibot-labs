"""
The event log the model learns from, kept in the store's Redis (a feature store in miniature).

W2 Ch7's ext (demo_site/ext/ml.py) writes here after every request; defenses/ml_check.py reads
here at checkout; tools/ export it into data/history/ for training. Nothing in this file
decides anything.

    lab:ml:ev:<sid>      list   one JSON event per request (server-side view: pacing, assets, headers)
    lab:ml:tel:<sid>     list   one JSON row per telemetry report (client-side view: fp, beh)
    lab:ml:login:<sid>   str    the account that session signed in to
    lab:ml:ip:<ip>       zset   sessions first seen on that address (score: first_ts)     -> cohort counts
    lab:ml:fp:<hash>     zset   "<sid>|<ip>" per fingerprint report (score: ts)           -> cohort counts
    lab:ml:review:<n>    str    a deferred-enforcement record (Round 4)

Everything lives under `lab:`, so POST /lab/reset wipes it with the rest of the lab state.
Timestamps are the caller's virtual clock when it sends X-Virtual-Ts (tools/shopper.py), else wall
seconds; the features read them as-is (no scaling). The wire is still compressed by LAB_TIME_SCALE
(defenses/features.py) — the sleeps are short — but that compression no longer touches the recorded
timeline, so a drop day of minutes runs in about a minute AND regenerates identically.
"""

import json

WINDOW_S = 3600            # the cohort window, in VIRTUAL seconds (defenses/cohort.py scales it)


def log_event(redis, ev):
    """Append one request event. The first event of a session registers it for cohort counts."""
    n = redis.rpush(f"lab:ml:ev:{ev['sid']}", json.dumps(ev))
    if n == 1:
        redis.zadd(f"lab:ml:ip:{ev['ip']}", {ev["sid"]: ev["ts"]})
    redis.expire(f"lab:ml:ev:{ev['sid']}", 24 * 3600)


def log_telemetry(redis, sid, row):
    redis.rpush(f"lab:ml:tel:{sid}", json.dumps(row))
    if row.get("fp_hash"):
        redis.zadd(f"lab:ml:fp:{row['fp_hash']}", {f"{sid}|{row['ip']}": row["ts"]})
    redis.expire(f"lab:ml:tel:{sid}", 24 * 3600)


def log_login(redis, sid, email):
    redis.set(f"lab:ml:login:{sid}", email, ex=24 * 3600)


def session_rows(redis, sid):
    """(events, telemetry, email-or-None) of one session, as plain dicts."""
    ev = [json.loads(x) for x in redis.lrange(f"lab:ml:ev:{sid}", 0, -1)]
    tel = [json.loads(x) for x in redis.lrange(f"lab:ml:tel:{sid}", 0, -1)]
    return ev, tel, redis.get(f"lab:ml:login:{sid}")


def window_rows(redis, start, end, ip, fp_hash):
    """
    Population rows a session's cohort features can match, inside (start, end]: the sessions
    first seen on its address and the sessions that reported the same fingerprint. Only
    matching rows are fetched, which keeps the cost flat as traffic grows.
    """
    sessions = [{"sid": sid, "ip": ip} for sid in redis.zrangebyscore(f"lab:ml:ip:{ip}", f"({start}", end)] if ip else []
    fps = []
    if fp_hash:
        for member in redis.zrangebyscore(f"lab:ml:fp:{fp_hash}", f"({start}", end):
            sid, _, fip = member.partition("|")
            fps.append({"sid": sid, "fp_hash": fp_hash, "ip": fip})
    return sessions, fps


def export(redis):
    """Everything logged since the last reset, for tools/ to append to the training history."""
    events, telemetry, logins = [], [], {}
    for key in redis.scan_iter("lab:ml:ev:*"):
        events += [json.loads(x) for x in redis.lrange(key, 0, -1)]
    for key in redis.scan_iter("lab:ml:tel:*"):
        sid = key.split(":", 3)[3]
        telemetry += [dict(json.loads(x), sid=sid) for x in redis.lrange(key, 0, -1)]
    for key in redis.scan_iter("lab:ml:login:*"):
        logins[key.split(":", 3)[3]] = redis.get(key)
    return {"events": events, "telemetry": telemetry, "logins": logins}
