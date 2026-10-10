"""
W3 Ch3 — The detector consumer

One process reads the event log as a consumer group and runs the detectors that
are turned on at the current DEFENSE_LEVEL. Levels are cumulative, so each round
adds a detector on top of the last:

    L1  window_rate                      (Round 1)
    L2  + heavy_hitters                  (Round 2)
    L3  + regularity + cross_key         (Round 3)
    L4  + composite                      (Round 4)

The Scorer folds one event at a time: it updates the session features and the
sketches once, hands the event to each enabled detector (each returns a soft
score in [0, 1] always, and a hard verdict when its own threshold trips), lets
the composite read the accumulated soft scores, and keeps each session's single
strongest verdict. `run()` drains the whole stream for the checkpoint; `serve()`
loops forever for the live Flask app. Both go through the same Scorer, so there
is one scoring path.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _d in ("demo_site", "defenses"):
    _p = os.path.join(ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import stream
from features import SessionFeatures, Sketches

import window_rate
import heavy_hitters
import regularity
import cross_key
import composite

HARD_DETECTORS = {
    1: [("window_rate", window_rate)],
    2: [("window_rate", window_rate), ("heavy_hitters", heavy_hitters)],
    3: [("window_rate", window_rate), ("heavy_hitters", heavy_hitters),
        ("regularity", regularity), ("cross_key", cross_key)],
    4: [("window_rate", window_rate), ("heavy_hitters", heavy_hitters),
        ("regularity", regularity), ("cross_key", cross_key)],
}
ACTION_RANK = {"allow": 0, "monitor": 1, "challenge": 2, "block": 3}
FLAGGED = ("challenge", "block")


def _better(a, b):
    """Keep the stronger of two verdicts (by action, then score)."""
    if a is None:
        return b
    if b is None:
        return a
    ka = (ACTION_RANK.get(a["action"], 0), a.get("bot_score", 0))
    kb = (ACTION_RANK.get(b["action"], 0), b.get("bot_score", 0))
    return b if kb > ka else a


class Scorer:
    """Stateful, incremental scoring for one DEFENSE_LEVEL."""

    def __init__(self, r, level):
        self.r = r
        self.level = level
        self.feats_store = SessionFeatures(r)
        self.sketches = Sketches(r)
        self.hard = HARD_DETECTORS.get(level, [])
        self.use_composite = level >= 4
        self.verdicts = {}     # sid -> strongest verdict
        self.softs = {}        # sid -> {detector: max soft}
        self.first_ts = {}     # sid -> first event ts
        self.detect_ts = {}    # sid -> ts that first flagged it

    def feed(self, event):
        """Fold one event; return this session's strongest verdict (or None)."""
        sid = event["sid"]
        self.first_ts.setdefault(sid, float(event["ts"]))
        self.softs.setdefault(sid, {})
        feats = self.feats_store.update(event)

        for name, mod in self.hard:
            soft, verdict = mod.detect(event, feats, self.sketches, self.r)
            if soft > self.softs[sid].get(name, 0.0):
                self.softs[sid][name] = soft
            if verdict is not None:
                self.verdicts[sid] = _better(self.verdicts.get(sid), verdict)
        if self.use_composite:
            _soft, verdict = composite.detect(event, feats, self.sketches, self.softs[sid], self.r)
            if verdict is not None:
                self.verdicts[sid] = _better(self.verdicts.get(sid), verdict)

        best = self.verdicts.get(sid)
        if best and best["action"] in FLAGGED and sid not in self.detect_ts:
            self.detect_ts[sid] = float(event["ts"])
        return best

    def stats(self, n_events, wall_s):
        pending, lag = stream.lag(self.r)
        ttd = [self.detect_ts[s] - self.first_ts[s] for s in self.detect_ts]
        return {
            "events": n_events,
            "wall_s": round(wall_s, 4),
            "events_per_s": round(n_events / wall_s, 1) if wall_s > 0 else 0.0,
            "pending": pending, "lag": lag,
            "flagged": sum(1 for v in self.verdicts.values() if v["action"] in FLAGGED),
            "time_to_detect_s": ttd,
        }


def run(r, level, consumer="c1", batch=1000, delay_per_event=0.0):
    """Drain the event log through the level's detectors. Returns (verdicts, stats)."""
    stream.ensure_group(r)
    scorer = Scorer(r, level)
    n_events = 0
    wall = time.perf_counter()
    while True:
        entries = stream.read_batch(r, consumer, count=batch)
        if not entries:
            break
        ids = []
        for msg_id, event in entries:
            ids.append(msg_id)
            n_events += 1
            if delay_per_event:
                time.sleep(delay_per_event)
            scorer.feed(event)
        stream.ack(r, ids)
    return scorer.verdicts, scorer.stats(n_events, time.perf_counter() - wall)


def serve(r, level, on_verdict, stop, consumer="c1"):
    """Loop forever for the live app: score each event and call on_verdict."""
    stream.ensure_group(r)
    scorer = Scorer(r, level)
    while not stop.is_set():
        entries = stream.read_batch(r, consumer, count=200, block=500)
        if not entries:
            continue
        ids = []
        for msg_id, event in entries:
            ids.append(msg_id)
            before = scorer.verdicts.get(event["sid"])
            after = scorer.feed(event)
            if after is not None and after is not before:
                on_verdict(after)
        stream.ack(r, ids)
