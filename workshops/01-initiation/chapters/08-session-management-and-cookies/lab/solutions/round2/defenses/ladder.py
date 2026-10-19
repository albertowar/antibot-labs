"""Reference ladder (W1 Ch8). Installed by tools/checkpoint.py --round N --catch-up.

Each level lists only the check it ADDS. The engine runs every level up to DEFENSE_LEVEL,
so a check named at two levels would run twice (and promo_state would consume its own unlock).
"""

from defenses import promo_state, session_velocity, session_guard

LADDER = {
    0: [],
    1: [promo_state.CHECK],
    2: [session_velocity.CHECK],
}
