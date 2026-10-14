"""
limiter_lab: the four algorithms, same traffic, injected clock. No store, no network.

Replays three request traces through the lab's REAL limiter functions and prints how many
each let through. Use it to feel the difference the slides and the content doc describe,
without waiting on wall-clock time:

    python tools/limiter_lab.py

    boundary    40 requests straddling a 10 s window edge (20 just before, 20 just after)
    human       one shopper, a request every few seconds for two minutes
    cgnat       six phones behind one address, ~60 requests spread over a minute

The point: fixed_window passes the whole boundary burst (twice its limit), while the token
bucket and the sliding-window counter hold the line; and all four punish the shared CGNAT
address, which is why the key you count on (Chapter's Round 4-5) matters as much as the
algorithm.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.abspath(os.path.join(HERE, "..")), HERE]

from defenses import fixed_window, policy, sliding_window, store  # noqa: E402

LADDER_FW = policy.FIXED_WINDOW          # (20, 10)
LADDER_SW = policy.SLIDING_WINDOW        # (30, 60)
BUCKET = policy.RATE_LIMITS["ip"]        # (20, 0.5)


def trace_boundary():
    """20 requests at t=9.9 s, then 20 at t=10.1 s: the fixed-window seam."""
    return [9.9 + 0.001 * i for i in range(20)] + [10.1 + 0.001 * i for i in range(20)]


def trace_human():
    """One shopper: a click every 4-6 s for two minutes."""
    t, out, step = 0.0, [], 4.5
    while t < 120:
        out.append(t)
        t += step
    return out


def trace_cgnat():
    """Six phones behind one address: ~60 requests spread evenly over 60 s."""
    return [i * (60.0 / 60) for i in range(60)]


def run_fixed(times, redis, key="k"):
    limit, window = LADDER_FW
    return sum(1 for t in times if fixed_window.hit(redis, key, limit, window, now=t)[0])


def run_sliding(times, redis, key="k"):
    limit, window = LADDER_SW
    return sum(1 for t in times if sliding_window.estimate(redis, key, limit, window, now=t)[0])


def run_bucket(times, redis, key="k"):
    cap, refill = BUCKET
    allowed = 0
    for t in times:
        store._now = t                                  # injected clock (see patch below)
        if store.token_bucket(redis, "ip", key):
            allowed += 1
    return allowed


def run_log(times, redis, key="k"):
    """The exact sliding-window LOG (store.Counters): correct, but O(requests) memory."""
    limit, window = LADDER_SW
    c = store.Counters(redis, "lab:ll:log")
    allowed = 0
    for t in times:
        # count within the window ending at t, then decide
        k = f"{c.prefix}:req:{key}"
        redis.zremrangebyscore(k, 0, t - window)
        if redis.zcard(k) < limit:
            redis.zadd(k, {f"{t}": t})
            allowed += 1
    return allowed


def _patch_bucket_clock():
    """Make store.token_bucket read store._now instead of wall-clock, for a repeatable trace."""
    import time as _time
    store._now = 0.0
    real = _time.time
    store_time = store.time
    store_time.time = lambda: getattr(store, "_now", real())


def main():
    _patch_bucket_clock()
    traces = {"boundary": trace_boundary(), "human": trace_human(), "cgnat": trace_cgnat()}
    print(f"{'trace':<10}{'n':>4}{'fixed':>8}{'sliding':>9}{'bucket':>8}{'log':>6}")
    print(f"           fixed_window{LADDER_FW}  sliding_window{LADDER_SW}  token_bucket{BUCKET}")
    for name, times in traces.items():
        r = store.get_redis("memory://")
        store.flush_lab_state(r)
        fw = run_fixed(times, r, name + "fw")
        sw = run_sliding(times, r, name + "sw")
        tb = run_bucket(times, r, name + "tb")
        lg = run_log(times, r, name + "lg")
        print(f"{name:<10}{len(times):>4}{fw:>8}{sw:>9}{tb:>8}{lg:>6}")


if __name__ == "__main__":
    main()
