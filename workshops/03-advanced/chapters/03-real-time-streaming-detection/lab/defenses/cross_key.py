"""
Round 3 defense (part B) — cross-key join: distinct IPs per username

This is the signal Workshop 2 said "belongs in Workshop 3". A low-and-slow
campaign sends one login attempt per IP per minute, rotating across hundreds of
IPs. Per IP it is indistinguishable from a slow human, so every per-IP signal
(the window, the sketches keyed on IP) stays quiet. The attack is only visible
when you pivot the key: look at one targeted *username* and count how many
distinct source IPs have tried to log into it.

A real account is used from a handful of IPs over an hour. An account that sees
logins from 60 different IPs in an hour is under a distributed attack, whatever
the per-IP rate. We track that distinct count with a HyperLogLog per username
over a long window (WINDOW_CROSS = 1 hour), because low-and-slow only shows up
when you look back far enough. When a user's fan-out crosses the threshold, the
sessions attacking that user are flagged.

False positives: a username typo collision (two people fighting over the same
email) or a genuinely popular shared test account. And a NAT'd office that logs
one person in from a pool of egress IPs can inflate the count. Keep the
threshold above plausible human sharing, and remember HyperLogLog is
approximate (~0.8% error), so treat a count near the threshold as "near", not
exact.
"""

USER_FANOUT = 20   # distinct source IPs attempting one username over the window


def detect(event, feats, sketches, r):
    path = event["path"]
    user = event.get("user", "")
    failed_login = path.startswith("/api/login") and event.get("status") in ("401", "403")
    if not failed_login or not user:
        return 0.0, None

    ts = float(event["ts"])
    sketches.add_user_ip(user, event["ip"], ts)
    fanout = sketches.distinct_ips_for_user(user, ts)

    soft = min(1.0, fanout / USER_FANOUT)
    if fanout >= USER_FANOUT:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "cross_key",
            "signal": "user_ip_fanout", "user": user, "distinct_ips": fanout,
            "bot_score": 0.9, "action": "block", "ts": ts,
        }
    return soft, None
