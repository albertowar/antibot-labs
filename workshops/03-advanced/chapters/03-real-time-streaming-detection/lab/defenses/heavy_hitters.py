"""
Round 2 defense — heavy hitters with probabilistic sketches

Round 1 keyed on the source IP, so the attacker spread the same burst across
many IPs, each one slow enough to stay under the per-IP window. No single IP is
a heavy hitter any more — but the *endpoint* is, and the *set of IPs failing
login* is huge. Both of those are expensive to track exactly at scale (a
counter and a set per endpoint, growing without bound), so we approximate:

  Count-Min sketch   failed logins per endpoint, in fixed memory with a small
                     over-count error — enough to see the velocity spike.
  HyperLogLog        distinct source IPs failing login, ~0.8% error in 12 KB,
                     instead of a set that grows with the botnet.
  Top-K              names the heaviest endpoints for the operator's report.

A velocity spike alone would flag everyone hitting a hot endpoint, including
humans. So the verdict needs a per-session discriminator: a session that is
failing logins, loading no assets, and never buying is stuffing-shaped. The
sketches turn that weak per-session signal into a campaign verdict. A human who
mistypes a password once is not failing N times with no assets.
"""

VELOCITY_THRESHOLD = 60   # failed logins to one endpoint in the velocity window
FANOUT_THRESHOLD = 25     # distinct source IPs failing login in the window
SESSION_FAILS = 3         # a stuffing-shaped session fails at least this many


def detect(event, feats, sketches, r):
    ts = float(event["ts"])
    path = event["path"]
    failed_login = path.startswith("/api/login") and event.get("status") in ("401", "403")
    if not failed_login:
        return 0.0, None

    # Update the global sketches for this failed login.
    sketches.bump_endpoint_fail(path, ts)
    sketches.bump_topk_endpoint(path, ts)
    sketches.add_fail_ip(event["ip"], ts)

    velocity = sketches.endpoint_fail_rate(path, ts)
    fanout = sketches.distinct_fail_ips(ts)
    campaign = velocity >= VELOCITY_THRESHOLD or fanout >= FANOUT_THRESHOLD

    stuffing_shape = feats["n_fail"] >= SESSION_FAILS and feats["n_asset"] == 0 and not feats["bought"]
    soft = min(1.0, max(velocity / VELOCITY_THRESHOLD, fanout / FANOUT_THRESHOLD)) if stuffing_shape else 0.0

    if campaign and stuffing_shape:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "heavy_hitters",
            "signal": "stuffing_campaign", "endpoint": path,
            "endpoint_fail_velocity": velocity, "distinct_fail_ips": fanout,
            "session_fails": feats["n_fail"], "bot_score": 0.9,
            "action": "block", "ts": ts,
        }
    return soft, None
