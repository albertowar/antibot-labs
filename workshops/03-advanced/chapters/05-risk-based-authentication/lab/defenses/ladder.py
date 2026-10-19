"""
The ladder: which checks run at which DEFENSE_LEVEL. (YOUR FILE: Rounds 1 and 3 wire into it.)

    level 0   W2 Ch6's finished login defenses, copied byte for byte: per-IP and per-account
              throttling, and the breached-password screen (a correct breached password steps up)
    level 1   stepup_policy: blanket_otp at level 1, then your risk model from level 2 (Round 1 wires it)
    level 3   recovery_risk: the password reset scored like a login (Round 3 wires it)

Level k is enforced when k <= DEFENSE_LEVEL. Change it, save, and the store picks it up on the
next request (LAB_RELOAD=1). Fell behind? `python tools/checkpoint.py --round N --catch-up`.
"""

from . import breached_passwords, login_throttle

LADDER = {
    0: [login_throttle.CHECK, breached_passwords.CHECK],
    # TODO (Round 1): 1: [stepup_policy.CHECK],     (import stepup_policy above)
    # TODO (Round 3): 3: [recovery_risk.CHECK],     (import recovery_risk above)
}
