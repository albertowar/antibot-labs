"""
W3 Ch3 — The event log (Redis Streams) and consumer-group helpers

Every HTTP request becomes one event appended to a Redis Stream with XADD. A
detector reads the stream as a *consumer group*: XREADGROUP hands each event to
exactly one consumer, the consumer XACKs it when done, and XINFO/XPENDING tell
you how far behind the group is (the "lag"). That lag is the honest cost of
streaming: if your detector is slower than the traffic, the lag grows and the
latency gap you came here to close reopens (Round 4).

Keys (all namespaced so reset() never touches another app's data):
    w3ch3:events     the append-only HTTP event log
    w3ch3:verdicts   verdicts the detectors emit
Everything else a detector keeps (windows, sketches, per-session state) is
created under the same w3ch3: prefix by the defense modules.
"""

PREFIX = "w3ch3:"
EVENTS = PREFIX + "events"
VERDICTS = PREFIX + "verdicts"
GROUP = "detectors"

# Stream values must be strings. These are the fields of one HTTP event.
FIELDS = ("ts", "sid", "ip", "path", "method", "status", "user", "ua", "is_asset", "actor")


def emit(r, event):
    """Append one HTTP event to the log. Returns the stream id."""
    flat = {k: str(event.get(k, "")) for k in FIELDS}
    return r.xadd(EVENTS, flat)


def ensure_group(r, group=GROUP):
    """Create the consumer group at the start of the stream, idempotently."""
    try:
        r.xgroup_create(EVENTS, group, id="0", mkstream=True)
    except Exception as exc:  # BUSYGROUP: the group already exists
        if "BUSYGROUP" not in str(exc):
            raise


def read_batch(r, consumer, count=500, block=None, group=GROUP):
    """Claim up to `count` new events for this consumer. Returns [(id, event)]."""
    resp = r.xreadgroup(group, consumer, {EVENTS: ">"}, count=count, block=block)
    if not resp:
        return []
    _stream, entries = resp[0]
    return [(sid, fields) for sid, fields in entries]


def ack(r, ids, group=GROUP):
    if ids:
        r.xack(EVENTS, group, *ids)


def lag(r, group=GROUP):
    """How far behind the group is: (pending, lag). pending = delivered-not-acked."""
    for g in r.xinfo_groups(EVENTS):
        if g.get("name") == group:
            return int(g.get("pending", 0) or 0), int(g.get("lag", 0) or 0)
    return 0, 0


def publish_verdict(r, verdict):
    import json
    r.xadd(VERDICTS, {"json": json.dumps(verdict)})


def reset(r):
    """Delete only this lab's keys. Never flushes the database."""
    keys = list(r.scan_iter(match=PREFIX + "*"))
    if keys:
        r.delete(*keys)
    return len(keys)
