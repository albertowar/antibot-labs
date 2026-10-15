"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets
level N. Level 0 is the bare store: nobody looks at who is crawling it. Change this file,
save, and the store picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference version of every
file a round changes, up to round N, and of this file.

Each round's layer is a module in defenses/ whose TODOs you finish first; wiring its CHECK
here is the second half. The layers talk to each other through the label in ctx.attrs["crawl"]
(see defenses/crawl.py), so they must stay in this order: claim, proof, behaviour, policy.
"""

from . import crawler_registry

LADDER = {
    0: [],
    1: [crawler_registry.CHECK],           # who claims to be a crawler, and what robots.txt says
}
