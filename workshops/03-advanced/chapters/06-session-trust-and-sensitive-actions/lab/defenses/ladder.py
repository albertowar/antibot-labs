"""
The ladder: which checks run at which DEFENSE_LEVEL. (Written for you: the rounds are in the files it names.)

    level 0   Chapter 5's login stack, finished: per-IP and per-account throttling, the breached-password screen,
              the risk-scored login (login_stack: stepup_policy + rba_score) and the risk-scored password reset
              (recovery_risk). It runs at every level, so every round starts where Chapter 5 ended.
    level 1   sudo_reauth: the password again before any sensitive action               (Round 1, yours)
    level 2   session_trust: a trust number, action weights, restricted mode             (Round 2, yours)
    level 3   stepup_channels: the factor that matches the weight and the account       (Round 3, yours)
    level 4   change_hold: cooling-off instead of refusal, notify every channel         (Round 4, yours)

Each round's check acts at its own level (or above, for Round 4) and replaces the previous round's rule, as in
Chapter 5. Level k is enforced when k <= DEFENSE_LEVEL; the files hot-reload.
Fell behind? `python tools/checkpoint.py --round N --catch-up`.
"""

from . import (breached_passwords, change_hold, login_stack, login_throttle, recovery_risk, session_trust,
               stepup_channels, sudo_reauth)

LADDER = {
    0: [login_throttle.CHECK, breached_passwords.CHECK, login_stack.CHECK, recovery_risk.CHECK],
    1: [sudo_reauth.CHECK],
    2: [session_trust.CHECK],
    3: [stepup_channels.CHECK],
    4: [change_hold.CHECK],
}
