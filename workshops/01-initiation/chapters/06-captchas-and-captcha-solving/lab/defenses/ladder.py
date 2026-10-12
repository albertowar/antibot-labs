"""
The ladder: which checks run at which DEFENSE_LEVEL. Chapter 6 ships it pre-wired: what you
edit in each round is the module the level uses (the TODO (Round N) markers), not this file.
Switch levels with `python tools/checkpoint.py --round N` (it sets the level for you) or by hand:
curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'

Level k is enforced when k <= DEFENSE_LEVEL. Edit a module under defenses/, save, and the store
picks it up on the next request (LAB_RELOAD=1).

    L1  turnstile_check   a provider token on sign-up and the newsletter    -> fix siteverify.py
    L2  captcha_gate      an image CAPTCHA on the promo voucher             -> fix challenge_store.py
    L3  (no new check)    the same gate; captcha_gate.issue() now draws the -> fix captcha_generator.py
                          hardened style (policy.HARDENED_FROM_LEVEL)
    L4  solver_signals    the CAPTCHA only for risky sessions, and every    -> fix solver_signals.py
                          solve is scored (captcha_gate steps aside)

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference version of
each module for rounds 1..N from solutions/ (your files are kept as <name>.py.bak).
"""

from . import captcha_gate, solver_signals, turnstile_check

LADDER = {
    0: [],
    1: [turnstile_check.CHECK],
    2: [captcha_gate.CHECK],
    3: [],
    4: [solver_signals.CHECK],
}
