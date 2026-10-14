"""
One record per gated request. Written through a queue and a flusher thread so
40 concurrent shoppers do not fight over the SQLite write lock in the request
path. /lab/decisions, /lab/scoreboard and /lab/reset flush first.

Also mirrored to DECISION_LOG as JSON lines, which is what the analysis
chapters read offline.
"""

import json
import queue
import threading


class DecisionLog:
    def __init__(self, app, db, model, jsonl_path=None):
        self.app, self.db, self.model, self.jsonl_path = app, db, model, jsonl_path
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._loop, daemon=True, name="decision-log")
        self.thread.start()

    def write(self, record: dict):
        self.q.put(record)

    def flush(self, timeout=5.0):
        """Block until everything queued so far is in the database."""
        done = threading.Event()
        self.q.put(done)
        done.wait(timeout)

    def _loop(self):
        while True:
            item = self.q.get()
            batch, events = [], []
            while True:
                if isinstance(item, threading.Event):
                    events.append(item)
                else:
                    batch.append(item)
                try:
                    item = self.q.get_nowait()
                except queue.Empty:
                    break
            if batch:
                self._persist(batch)
            for e in events:
                e.set()

    def _persist(self, batch):
        with self.lock, self.app.app_context():
            try:
                self.db.session.add_all([self.model(**r) for r in batch])
                self.db.session.commit()
            except Exception:
                self.db.session.rollback()
            if self.jsonl_path:
                try:
                    with open(self.jsonl_path, "a") as f:
                        for r in batch:
                            f.write(json.dumps(r, default=str) + "\n")
                except OSError:
                    pass
