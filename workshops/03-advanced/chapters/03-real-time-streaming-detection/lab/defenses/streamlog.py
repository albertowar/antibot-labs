"""
The event log (a Redis Stream), the consumer-group helpers and the verdict flags.

Every gated request becomes one event appended to a Redis Stream with XADD
(demo_site/ext/stream.py does that after the route has answered). A detector
reads the stream as a *consumer group*: XREADGROUP hands each event to exactly
one consumer, the consumer XACKs it when it is done, and XINFO says how far
behind the group is (the "lag"). Lag is the honest cost of streaming: when the
detector is slower than the traffic, the backlog grows and the verdict reaches
the gate after the attacker is done.

A verdict is useless until something enforces it, so the loop is closed here:

    request -> route -> XADD event -> consumer scores it -> raise_flag(...)
                                                               |
    next request -> the detector's Check (enforcer) -> MGET flag keys -> Signal / Verdict

Scoring is asynchronous (the log, the lag); the lookup at the gate is a single MGET. That split is
how production streaming defenses work: the decision store is read-fast, and the scorer is
allowed to be a little behind. Every key lives under `lab:stream:`, so POST /lab/reset (which
flushes `lab:*`) leaves the next round clean.

Lab clock. Windows are shorter than production so a round fits in under a minute:
rate 10 s (production: 60), failed-login velocity 60 s (600), distinct IPs per account 120 s
(3600). The sketch windows are tumbling and aligned to the first event after a reset (`epoch`),
so a round never straddles a boundary by accident; a real deployment has no such luck, which is
why production uses sliding or hopping windows.
"""

import json
import time

from .pipeline import Signal, Verdict

PREFIX = "lab:stream:"
EVENTS = PREFIX + "events"
VERDICTS = PREFIX + "verdicts"
EPOCH = PREFIX + "epoch"
GROUP = "detectors"
FLAG_TTL = 120          # seconds a flag blocks its subject (the lab clock; production: minutes to hours)
MAXLEN = 50000          # trim the log (approximately) so a long session cannot fill memory

# Stream values are strings. These are the fields of one HTTP event.
FIELDS = ("ts", "sid", "ip", "path", "method", "status", "user", "page", "login_failed", "bought")


def emit(r, event):
    """Append one HTTP event to the log. Returns the stream id."""
    flat = {k: str(event.get(k, "")) for k in FIELDS}
    return r.xadd(EVENTS, flat, maxlen=MAXLEN, approximate=True)


def ensure_group(r, group=GROUP):
    """Create the consumer group at the start of the stream, idempotently."""
    try:
        r.xgroup_create(EVENTS, group, id="0", mkstream=True)
    except Exception as exc:                      # BUSYGROUP: the group already exists
        if "BUSYGROUP" not in str(exc):
            raise


def read_batch(r, consumer, count=200, group=GROUP):
    """Claim up to `count` new events for this consumer. Returns [(id, event)].

    Production blocks here (XREADGROUP ... BLOCK ms); the lab polls, so a store reset that deletes
    the stream and the group cannot leave a reader stuck. A missing stream or group is recreated.
    """
    try:
        resp = r.xreadgroup(group, consumer, {EVENTS: ">"}, count=count)
    except Exception as exc:
        if "NOGROUP" in str(exc) or "requires the key" in str(exc):
            ensure_group(r, group)
            return []
        raise
    if not resp:
        return []
    return [(sid, fields) for sid, fields in resp[0][1]]


def ack(r, ids, group=GROUP):
    if ids:
        r.xack(EVENTS, group, *ids)


def backlog(r, group=GROUP):
    """(pending, lag): delivered-but-not-acked, and not-yet-delivered. Their sum is the backlog."""
    try:
        for g in r.xinfo_groups(EVENTS):
            if g.get("name") == group:
                return int(g.get("pending") or 0), int(g.get("lag") or 0)
    except Exception:
        pass
    return 0, 0


def epoch(r, ts):
    """The lab clock's zero: the timestamp of the first event after a reset (set once, NX)."""
    r.set(EPOCH, f"{ts}", nx=True)
    return float(r.get(EPOCH) or ts)


# --- Flags: the verdict, in a place the gate can read in one round trip -----------------------

def flag_key(detector, kind, value):
    return f"{PREFIX}flag:{detector}:{kind}:{value}"


def raise_flag(r, verdict, lag_ms=0.0):
    """Record a verdict: a TTL'd flag on its subject, plus a line in the verdict log (for the lab tools)."""
    kind, value = verdict["subject"]
    body = {k: v for k, v in verdict.items() if k != "subject"}
    body.update(kind=kind, value=value, flag_at=round(time.time(), 3))
    key = flag_key(verdict["detector"], kind, value)
    fresh = not r.exists(key)                      # a flag that is still up is refreshed, not logged again
    r.set(key, json.dumps(body), ex=FLAG_TTL)
    if fresh:
        r.xadd(VERDICTS, {"json": json.dumps(dict(body, lag_ms=round(lag_ms, 1)))}, maxlen=5000, approximate=True)


def submitted_email(ctx):
    """The account a login request names (what the cross-key join pivots on), else ''."""
    if ctx.method != "POST" or ctx.path not in ("/api/login", "/login"):
        return ""
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return str((body or {}).get("email", "")).strip().lower()


def enforcer(detector, kinds):
    """
    The gate half of a detector: a Check function that looks up the flags `detector` raised for this
    request's subjects (`ip`, `sid`, `user`) and answers with a Signal on the policy scale, or a hard
    block when the detector said block. One MGET; no scoring happens here.
    """
    def _check(ctx):
        subjects = []
        if "ip" in kinds:
            subjects.append(("ip", ctx.ip))
        if "sid" in kinds:
            subjects.append(("sid", ctx.session.sid))
        if "user" in kinds and submitted_email(ctx):
            subjects.append(("user", submitted_email(ctx)))
        if not subjects:
            return None
        raws = ctx.redis.mget([flag_key(detector, k, v) for k, v in subjects])
        for (kind, _v), raw in zip(subjects, raws):
            if not raw:
                continue
            flag = json.loads(raw)
            points = int(round(100 * float(flag.get("bot_score", 0.9))))
            sig = Signal(detector, flag.get("signal", "flag"), points, f"{kind} flagged")
            ctx.note(stream_flag=f"{detector}:{flag.get('signal')}", flagged_subject=kind)
            if flag.get("action") == "block":
                return Verdict("block", score=points, signals=(sig,))
            return [sig]
        return None
    return _check
