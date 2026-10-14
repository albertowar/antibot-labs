"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.
Change it, save, and the store picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference version for rounds 1..N.
"""

# from . import form_traps, crawl_traps, responses     # 1. import the round's check module(s)

LADDER = {
    0: [],
    # TODO (Round 1): 1: [form_traps.HONEYPOT_CHECK] — the textbook honeypot field.
    # TODO (Round 2): 2: [form_traps.TIMING_CHECK] — and fix HONEYPOT in form_traps.py before you trust it.
    # TODO (Round 3): 3: [crawl_traps.CHECK] — the trap link, the honey SKU and the decoys.
    # TODO (Round 4): 4: [responses.CHECK] — what the client gets AFTER a hit (policy.py picks the mode).
}
