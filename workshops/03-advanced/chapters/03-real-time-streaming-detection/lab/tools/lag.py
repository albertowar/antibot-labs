"""
Consumer lag: when the detector falls behind, the gap reopens.

Streaming only beats batch while the consumer keeps up. This tool makes the backlog visible. It
sets the store to level 1, slows the consumer with the lag knob (POST /lab/stream/consumer, a
`delay_ms` of work per event), fires Round 1's micro-burst (300 logins at 30 per second) and prints,
twice a second, how many events have arrived, how many the consumer has handled, and the backlog:
the consumer group's `pending + lag`.

While the consumer is faster than the traffic the backlog stays near zero and a flag lands within
milliseconds. When it is slower, the backlog grows without bound; the flag for the 21st request is
not computed until the consumer reaches it, and the attacker keeps being served in the meantime.
The fix is horizontal: more consumers in the group (`--consumers`), which is the operations story
of W3 Ch4. Nothing here is a pass/fail number: the backlog depends on your machine, so read the
shape of the table, not the digits.

    python tools/lag.py                          # a consumer that costs 100 ms per event: falls behind
    python tools/lag.py --delay-ms 0             # the fast consumer: the backlog never builds
    python tools/lag.py --delay-ms 100 --consumers 6   # six consumers in the group keep up

Needs the store running (python demo_site/app.py) or run it through `python tools/verify.py`'s store.
"""

import argparse
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import checkpoint_core  # noqa: E402
import labclient  # noqa: E402


def tune(**body):
    return labclient.admin("POST", "/lab/stream/consumer", json=body)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--delay-ms", type=float, default=100.0, help="work per event in the consumer (default 100)")
    ap.add_argument("--consumers", type=int, default=1, help="consumers in the group (default 1)")
    ap.add_argument("--level", type=int, default=1, help="DEFENSE_LEVEL to run at (default 1: the sliding window)")
    args = ap.parse_args()

    labclient.wait_for_store()
    labclient.set_level(args.level)
    labclient.reset()
    start = labclient.admin("GET", "/lab/stream/status")
    tune(delay_ms=args.delay_ms, consumers=args.consumers)
    print(f"level {args.level} · {args.consumers} consumer(s) at {args.delay_ms:.0f} ms per event "
          f"(capacity ~{args.consumers * 1000 / args.delay_ms:.0f} events/s)" if args.delay_ms else
          f"level {args.level} · {args.consumers} consumer(s), no added work")
    print("firing the micro-burst: 300 logins at 30 per second, from one IP\n")

    out = {}
    done = threading.Event()

    def attack():
        out.update(checkpoint_core.run_attack("attacks/round1_microburst.py"))
        done.set()

    threading.Thread(target=attack, daemon=True).start()
    print(f"{'t(s)':>5} {'arrived':>8} {'handled':>8} {'backlog':>8}")
    t0, peak, drained_at = time.time(), 0, None
    try:
        while True:
            st = labclient.admin("GET", "/lab/stream/status")
            peak = max(peak, st["backlog"])
            print(f"{time.time() - t0:5.1f} {st['events']:8d} {st['processed'] - start['processed']:8d} {st['backlog']:8d}")
            if done.is_set() and st["backlog"] == 0:
                drained_at = time.time() - t0
                break
            if time.time() - t0 > 300:
                break
            time.sleep(0.5)
    finally:
        tune(delay_ms=0, consumers=1)
    attack_s = out.get("duration_s")
    print(f"\nthe attack ran {attack_s} s; the first refusal came {out.get('first_block_after_s')} s in, "
          f"after {out.get('served_before_first_block')} logins were served; {out.get('succeeded')}/{out.get('attempted')} were served in all.")
    print(f"peak backlog {peak} events; the consumer " + (f"was caught up {drained_at:.1f} s after the burst began." if drained_at else "had not caught up when we stopped."))
    print(json.dumps({"peak_backlog": peak, "served": out.get("succeeded"), "first_block_after_s": out.get("first_block_after_s")}))


if __name__ == "__main__":
    main()
