"""
The ladder: which checks run at which DEFENSE_LEVEL. Chapter 3 ships it pre-written: you read each
round's defense, then switch levels (`python tools/checkpoint.py --round N` sets the level for you;
by hand: `curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'`).

Level k is enforced when k <= DEFENSE_LEVEL. Cheapest and most certain first inside a level. Edit a
module under defenses/, save, and the store picks it up on the next request.

    L1  ua_inspector      the User-Agent on its own: libraries, CLI tools, headless markers, stale versions
    L2  header_inspector  Accept*, Fetch Metadata and Referer: do the headers tell one story?
    L3  client_hints      Sec-CH-UA* against the User-Agent
        header_order      Chromium's header order
    L4  accept_ch         the high-entropy hints a real Chromium sends after Accept-CH
                          (the Accept-CH header itself comes from demo_site/ext/headers.py)

Points from every check add up (policy.BANDS): 20+ is logged as suspicious, 40+ is blocked.

Fell behind? `python tools/checkpoint.py --round N --catch-up` reinstalls the reference `defenses/ladder.py`
from solutions/round1..N.
"""

from . import accept_ch, client_hints, header_inspector, header_order, ua_inspector

LADDER = {
    0: [],
    1: [ua_inspector.CHECK],
    2: [header_inspector.CHECK],
    3: [client_hints.CHECK, header_order.CHECK],
    4: [accept_ch.CHECK],
}
