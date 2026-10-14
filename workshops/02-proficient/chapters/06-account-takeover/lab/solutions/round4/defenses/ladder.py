"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 4.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 4` sets level 4.
Round 4 adds the device and network risk engine and the fresh-proof gate on sensitive changes.
Order matters inside a level only for cost; the breached-password check must run before the risk
engine because it tells it (ctx.attrs["stepup"]) not to remember a login that needed a code.
"""

from . import breached_passwords, login_throttle, oracles, population_signals, risk_engine

LADDER = {
    0: [],
    1: [login_throttle.CHECK],
    2: [population_signals.CHECK],
    3: [breached_passwords.CHECK, oracles.CHECK],
    4: [risk_engine.CHECK, risk_engine.REAUTH],
}
