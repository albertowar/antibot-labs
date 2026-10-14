"""
flood_monitor (Round 1): see the flood before you limit it.

    policy.FLOOD_MONITOR = (threshold, window)    60 requests from one address in 60 s
    policy.FLOOD_MONITOR_POINTS = 20              the monitor band: logged, served, never blocked

Count every request per client address in a sliding log (store.Counters: one sorted set per
address, one member per request) and, past the threshold, add a signal worth the monitor
band. The store still serves the request. The decision log (/lab/decisions) and the
X-Lab-Signals header now name the flood, and the scoreboard shows what it cost.

Why start with a check that blocks nothing? The first thing a limit needs is a number, and
the only honest source of that number is your own traffic. Run the monitor, read who crossed
the line, and you know who a limit at that line would have stopped before it stops them.

What it catches: nothing. It only sees volume from one address.
What it misses: anything spread over many addresses, and anything slower than the threshold.
Who it hurts: nobody, by construction. Read the log for the shoppers it tagged anyway: they
are the false positives of every per-address limit you write after this one.
Cost: one sorted-set write per request, and memory per request per address for a minute.
That is fine for a monitor; it is the reason the real limiters below use plain counters.

Keys on client_ip(ctx).
"""

from . import policy
from .client_ip import client_ip
from .pipeline import Check, Signal
from .store import Counters


def _check(ctx):
    ip = client_ip(ctx)
    threshold, window = policy.FLOOD_MONITOR
    n = Counters(ctx.redis, "lab:fm").hit("req", ip, window)
    if n > threshold:
        return [Signal("flood_monitor", "high_rate", policy.FLOOD_MONITOR_POINTS, f"{ip} {n}/{window}s")]
    return None


CHECK = Check("flood_monitor", _check)
