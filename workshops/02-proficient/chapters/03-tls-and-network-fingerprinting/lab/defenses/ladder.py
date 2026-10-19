"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets
level N. Level 0 is the bare store: every request is fingerprinted and logged, nothing is refused.
Change this file, save, and the store picks it up on the next request (LAB_RELOAD=1). Fell
behind? `python tools/checkpoint.py --round N --catch-up` installs the reference version of the
round's check and of this file.

Each round's check is a stub you finish first (the `TODO (Round N)` in defenses/<check>.py);
wiring it here is the second half.
"""

# from . import ja4_denylist          # 1. import the round's check module

LADDER = {
    0: [],
    # TODO (Round 1): 1: [ja4_denylist.CHECK] — block the JA4 of HTTP libraries (and the requests that skipped the edge).
    # TODO (Round 2): 2: [tls_family.CHECK] — the User-Agent's browser must match the TLS family.
    # TODO (Round 3): 3: [h2_fingerprint.CHECK] — the HTTP/2 preface must match the TLS family.
    # TODO (Round 4): 4: [browser_proof.CHECK] — browser TLS needs a JavaScript engine of the same family.
}
