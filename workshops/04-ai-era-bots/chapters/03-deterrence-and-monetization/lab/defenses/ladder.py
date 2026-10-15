"""
The ladder: which checks run at which DEFENSE_LEVEL. (Pre-wired in this lab: the rounds are the
modules you fill in, not the wiring. A check you have not finished is inert.)

    level 0   nothing: every request is served
    level 1   bot_identity (who is this?) and crawl_policy (the published rules; breaches are logged)
    level 2   enforce (refuse crawlers that break the rules or cannot prove who they are)
    level 3   maze (a tagged client gets decoy pages instead of the catalogue)
    level 4   paywall (a verified crawler licensed for a purpose pays per request)

Level k is enforced when k <= DEFENSE_LEVEL. The verdict set is closed (allow, monitor, challenge,
block, rate_limit, deceive): `enforce` is a real `block`; the maze and the paywall are answered by
`demo_site/ext/deterrence.py` from what these checks record in `ctx.attrs`.

Change a module, save, and the store picks it up on the next request (LAB_RELOAD=1).
Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference modules for
rounds 1..N.
"""

from . import bot_identity, crawl_policy, enforce, maze, paywall

LADDER = {
    0: [],
    1: [bot_identity.CHECK, crawl_policy.CHECK],
    2: [enforce.CHECK],
    3: [maze.CHECK],
    4: [paywall.CHECK],
}
