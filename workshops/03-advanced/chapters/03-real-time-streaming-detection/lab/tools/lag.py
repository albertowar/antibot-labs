"""
W3 Ch3 — Consumer lag: when the detector falls behind, the gap reopens

Streaming only beats batch if the consumer keeps up with the stream. This tool
makes that visible. A producer thread appends login events at a chosen rate
while a consumer drains them at a chosen (slower) rate. Every tick it prints how
many events have arrived, how many have been processed, and the backlog — the
Redis consumer-group lag (delivered-but-unacked plus not-yet-delivered).

When the consumer is faster than the producer, the backlog stays near zero and
verdicts are real-time. When it is slower, the backlog grows without bound and a
verdict for an event that arrived now will not be computed until seconds later —
the latency gap you closed in Round 1, reopened by operational reality. The fix
is horizontal scale (more consumers in the group) and is the ops story of W3
Ch4.

    python tools/lag.py                      # consumer keeps up
    python tools/lag.py --produce 400 --consume 120   # consumer falls behind
"""

import argparse
import threading
import time

import lab  # noqa: F401
import store
import stream


def produce(r, n, rate, done):
    for i in range(n):
        stream.emit(r, {"ts": time.time(), "sid": f"s{i}", "ip": "198.51.100.1",
                        "path": "/api/login", "status": "401", "actor": "bot:lagdemo"})
        time.sleep(1.0 / rate)
    done.set()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--produce", type=int, default=300, help="events to produce")
    ap.add_argument("--rate", type=float, default=200, help="produce rate (events/s)")
    ap.add_argument("--consume", type=float, default=300, help="consume rate (events/s)")
    args = ap.parse_args()

    r = store.connect()
    stream.reset(r)
    stream.ensure_group(r)
    done = threading.Event()

    producer = threading.Thread(target=produce, args=(r, args.produce, args.rate, done))
    producer.start()

    processed = 0
    delay = 1.0 / args.consume
    print(f"producing {args.produce} at {args.rate:.0f}/s, consuming at {args.consume:.0f}/s\n")
    print(f"{'t(s)':>5} {'arrived':>8} {'processed':>10} {'backlog':>8}")
    t0 = time.time()
    next_print = t0
    while not done.is_set() or stream.lag(r)[0] + stream.lag(r)[1] > 0:
        batch = stream.read_batch(r, "c1", count=max(1, int(args.consume / 10)))
        if batch:
            time.sleep(delay * len(batch))
            stream.ack(r, [mid for mid, _ in batch])
            processed += len(batch)
        now = time.time()
        if now >= next_print:
            pending, lag = stream.lag(r)
            arrived = r.xlen(stream.EVENTS)
            print(f"{now - t0:5.1f} {arrived:8d} {processed:10d} {pending + lag:8d}")
            next_print = now + 0.5
        if not batch and not done.is_set():
            time.sleep(0.01)

    producer.join()
    pending, lag = stream.lag(r)
    verdict = "kept up" if (pending + lag) == 0 and args.consume >= args.rate else "fell behind"
    print(f"\nconsumer {verdict}. Final backlog: {pending + lag}. "
          f"A backlog that grows means verdicts arrive late — scale consumers (W3 Ch4).")


if __name__ == "__main__":
    main()
