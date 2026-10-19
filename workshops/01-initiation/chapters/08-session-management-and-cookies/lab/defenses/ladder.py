"""
The ladder: which checks run at which DEFENSE_LEVEL. (YOUR FILE in this pre-written lab.)

Each level lists only the check it ADDS. The engine runs every level up to DEFENSE_LEVEL,
cheapest and most certain first. (Name a check at two levels and it runs twice.) Save and
the store reloads it (LAB_RELOAD=1).

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference ladder
(and, for Round 3, the tuned policy) for rounds 1..N.
"""

# from defenses import promo_state, session_velocity, session_guard

LADDER = {
    0: [],
    # 1: [promo_state.CHECK],               # Round 1: trust the server session, not the cookie
    # 2: [session_velocity.CHECK],          # Round 2: rate-limit new sessions per IP
    # 3: [session_guard.CHECK],             # Round 3: read landing / js_ok / age at redeem
    # 4: [session_guard.BINDING_CHECK],     # Round 4: bind the session to its browser + network
}
