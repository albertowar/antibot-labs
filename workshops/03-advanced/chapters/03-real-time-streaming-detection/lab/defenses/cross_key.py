"""
Round 3 defense (part B): cross-key join, distinct IPs per account.

A low-and-slow campaign sends one login attempt per IP, rotating across hundreds of IPs. Per IP
it is indistinguishable from a slow human, so every per-IP signal (the window, the sketches keyed
on IP) stays quiet. The attack is only visible when you pivot the key: look at one targeted
*account* and count how many distinct source IPs have failed to log into it.

A real account is used from a handful of IPs over an hour. An account that sees failed logins
from 20 different IPs is under a distributed attack, whatever the per-IP rate. We track the
distinct count with a HyperLogLog per account over the longest window of the lab (WINDOW_CROSS),
because low-and-slow only shows up when you look back far enough. When the fan-out crosses the
threshold the *account* is flagged: from then on every login attempt that names it is refused,
whatever IP it comes from.

The price, stated plainly: until the 20th distinct IP the attempts were served (that is the
latency of distinct counting), and once the account is flagged its real owner is refused too
(in production you step the owner up instead of blocking, and you tell them).

Other false positives: two people fighting over one email, a genuinely popular shared test
account, a NAT'd office whose users arrive from a pool of egress IPs. Keep the threshold above
plausible human sharing, and treat a HyperLogLog count near it as "near" (~0.8% error).
"""

from . import streamlog
from .pipeline import Check

USER_FANOUT = 20   # distinct source IPs failing login for one account over the window


def detect(event, feats, sketches, softs, r):
    user = event.get("user", "")
    if event.get("login_failed") != "1" or not user:
        return 0.0, None
    ts = float(event["ts"])
    sketches.add_user_ip(user, event["ip"], ts)
    fanout = sketches.distinct_ips_for_user(user, ts)
    soft = min(1.0, fanout / USER_FANOUT)
    if fanout >= USER_FANOUT:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "cross_key", "signal": "user_ip_fanout",
            "subject": ("user", user), "user": user, "distinct_ips": fanout, "bot_score": 0.9,
            "action": "block", "ts": ts,
        }
    return soft, None


CHECK = Check("cross_key", streamlog.enforcer("cross_key", ("user",)))
