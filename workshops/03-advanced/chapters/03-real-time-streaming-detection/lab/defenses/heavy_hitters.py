"""
Round 2 defense: heavy hitters with probabilistic sketches.

Round 1 keyed on the source IP, so the attacker spread the same campaign across many IPs, each
one slow enough to stay under the per-IP window. No single IP is a heavy hitter any more, but
the *endpoint* is, and the *set of IPs failing login* is huge. Both are expensive to track
exactly at scale (a counter and a set per endpoint, growing without bound), so we approximate:

  Count-Min sketch   failed logins per endpoint, in fixed memory with a small over-count error.
  HyperLogLog        distinct source IPs failing login, ~0.8% error in 12 KB, instead of a set
                     that grows with the botnet.
  Top-K              names the heaviest endpoints for the operator's report.

A velocity spike alone would flag everyone hitting a hot endpoint, humans included. So the
verdict needs a per-session discriminator: a session that fails SESSION_FAILS logins, views no
page and never buys is stuffing-shaped. A person who mistypes a password once or twice, then
browses, is not. The sketches turn that weak per-session signal into a campaign verdict, and the
flag lands on the session: the attacker's next try from that session is refused.

Who it hurts: a customer who fails three logins in a row (a forgotten password) during someone
else's campaign, before they have viewed a page, looks like the attacker. The gate is keyed on
the session, so it costs that one visit, not the IP.
"""

from . import streamlog
from .pipeline import Check

VELOCITY_THRESHOLD = 60   # failed logins to one endpoint in the velocity window
FANOUT_THRESHOLD = 25     # distinct source IPs failing login in the window
SESSION_FAILS = 3         # a stuffing-shaped session has failed at least this many


def detect(event, feats, sketches, softs, r):
    if event.get("login_failed") != "1":
        return 0.0, None
    ts, path = float(event["ts"]), event["path"]

    sketches.bump_endpoint_fail(path, ts)
    sketches.bump_topk_endpoint(path, ts)
    sketches.add_fail_ip(event["ip"], ts)

    velocity = sketches.endpoint_fail_rate(path, ts)
    fanout = sketches.distinct_fail_ips(ts)
    campaign = velocity >= VELOCITY_THRESHOLD or fanout >= FANOUT_THRESHOLD

    shape = feats["n_fail"] >= SESSION_FAILS and feats["n_page"] == 0 and not feats["bought"]
    soft = min(1.0, max(velocity / VELOCITY_THRESHOLD, fanout / FANOUT_THRESHOLD)) if shape else 0.0
    if campaign and shape:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "heavy_hitters", "signal": "stuffing_campaign",
            "subject": ("sid", event["sid"]), "endpoint": path, "endpoint_fail_velocity": velocity,
            "distinct_fail_ips": fanout, "session_fails": feats["n_fail"], "bot_score": 0.9,
            "action": "block", "ts": ts,
        }
    return soft, None


CHECK = Check("heavy_hitters", streamlog.enforcer("heavy_hitters", ("sid",)))
