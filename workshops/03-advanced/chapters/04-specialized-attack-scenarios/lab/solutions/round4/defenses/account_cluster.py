"""
account_cluster (Round 4, reference): the signal in a fake-account farm is the cluster, not the account.

The economics. A farm profits from VOLUME, so attack the costs it tried to avoid, cheapest first:
  1. a disposable email domain      (the farm did not buy real inboxes)         100 -> block
  2. registrations per egress       (the farm rented one or a few boxes)         45 each
  3. accounts per device            (the farm reuses a few browser profiles)     45 each
Signals add up on the starter's scale: one velocity signal alone lands in the challenge band (an
emailed code), both together reach 90 and block. They are scoring inputs, not independent bans.

The challenge is the `otp` type from demo_site/ext/step_up.py: the store emails a code to the address
being registered and the sign-up goes through once it is entered. The farm does not read thousands of
inboxes; a real person behind a shared address does.

Who it hurts. Carrier-grade NAT, campuses and offices put many real first-time customers behind one
egress, and privacy browsers make many share one device id. Here, three of the six phones on the
shared carrier address are asked for a code. Derive the caps from your real per-IP registration
distribution. What it misses: a farm that spends on a residential-proxy fleet and a fresh browser
profile per account, which is the next chapter's economics: attackers pay for what you meter.
"""

from . import store
from .pipeline import Check, Signal, Verdict

IP_CAP = 3
DEVICE_CAP = 2
WINDOW_S = 300


def _check(ctx):
    signup = ctx.attrs.get("signup")
    if not signup:
        return None
    signals = []
    if signup["disposable"]:
        signals.append(Signal("signup", "disposable_domain", 100, signup["domain"]))
    counters = store.Counters(ctx.redis)
    from_egress = counters.hit("signup_ip", ctx.ip, WINDOW_S)
    from_device = counters.hit("signup_device", signup["device"], WINDOW_S)
    if from_egress > IP_CAP:
        signals.append(Signal("signup", "egress_velocity", 45, f"{from_egress} sign-ups from this egress"))
    if from_device > DEVICE_CAP:
        signals.append(Signal("signup", "device_cluster", 45, f"{from_device} accounts from this device"))
    if not signals:
        return None
    return Verdict("challenge", challenge="otp", signals=tuple(signals))


CHECK = Check("account_cluster", _check, phases=("action:register",))
