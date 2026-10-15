"""
The detector consumer: reads the event stream as a consumer group and runs the detectors the
ladder enables at the current DEFENSE_LEVEL.

The Scorer folds one event at a time: it updates the session features once, hands the event to
each enabled detector (each returns a soft score in [0, 1] always, and a verdict when its own
threshold trips), keeps each session's best soft score per detector, and raises a flag for every
verdict (streamlog.raise_flag). It holds no state of its own: features, soft scores and sketches
are all in Redis, so a second consumer in the group scores the same stream consistently and a
store reset (which deletes the stream and every key) cannot leave stale state behind.

Level 0 enables nothing: the consumer still reads and acknowledges the log (the cost of having a
stream) but scores nothing.

demo_site/ext/stream.py runs `step()` in a thread of the store process, as a sidecar worker would
in production. The consumer lives in the store's process because the zero-Docker store keeps Redis
in-process (memory://); against a real Redis the same function can run anywhere.
"""

import importlib
import time

from . import reloader, streamlog
from .features import WINDOW_CROSS, SessionFeatures, Sketches


def enabled(level, lab_reload=True):
    """The detector modules the ladder turns on at `level`: [(name, module)], in ladder order."""
    if lab_reload:
        ladder = reloader.ladder()
    else:
        from . import ladder as ladder_mod
        ladder = ladder_mod.LADDER
    out = []
    for k in sorted(ladder):
        if k > level:
            continue
        for check in ladder[k]:
            try:
                mod = importlib.import_module(f"defenses.{check.name}")
            except ImportError:
                continue
            if hasattr(mod, "detect"):
                out.append((check.name, mod))
    return out


class Scorer:
    """Stateless between events: everything it needs is in Redis."""

    def __init__(self, r):
        self.r = r

    def feed(self, event, sketches, detectors, lag_ms=0.0):
        r = self.r
        feats = SessionFeatures(r).update(event)
        soft_key = f"{streamlog.PREFIX}soft:{event['sid']}"
        softs = r.hgetall(soft_key)
        for name, mod in detectors:
            soft, verdict = mod.detect(event, feats, sketches, softs, r)
            if soft > float(softs.get(name, 0.0)):
                softs[name] = soft
                r.hset(soft_key, name, soft)
            if verdict is not None:
                streamlog.raise_flag(r, verdict, lag_ms)
        if softs:
            r.expire(soft_key, WINDOW_CROSS)


def step(r, consumer, level, lab_reload=True, count=200, delay_s=0.0, counter=None):
    """Claim one batch, score it, acknowledge it. Returns the number of events handled.

    `counter` (a dict with a "processed" key) is bumped per event, so a status endpoint can show progress.
    """
    entries = streamlog.read_batch(r, consumer, count=count)
    if not entries:
        return 0
    detectors = enabled(level, lab_reload)
    if detectors:
        sketches = Sketches(r, streamlog.epoch(r, float(entries[0][1]["ts"])))
        scorer = Scorer(r)
    for msg_id, event in entries:
        if delay_s:
            time.sleep(delay_s)            # a slow consumer: the lag knob (POST /lab/stream/consumer)
        if detectors:
            scorer.feed(event, sketches, detectors, lag_ms=(time.time() - float(event["ts"])) * 1000)
        streamlog.ack(r, [msg_id])
        if counter is not None:
            counter["processed"] += 1
    return len(entries)
