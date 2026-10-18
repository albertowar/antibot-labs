"""
The ladder: which checks run at which DEFENSE_LEVEL. (Reference after Round 1.)

    level 0   W2 Ch6's finished login defenses, copied byte for byte: per-IP and per-account
              throttling, and the breached-password screen (a correct breached password steps up)
    level 1   stepup_policy: blanket_otp at level 1, then your risk model from level 2
"""

from . import breached_passwords, login_throttle, stepup_policy

LADDER = {
    0: [login_throttle.CHECK, breached_passwords.CHECK],
    1: [stepup_policy.CHECK],
}
