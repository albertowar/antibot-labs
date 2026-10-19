"""
account_cluster (Round 4): the signal in a fake-account farm is the cluster, not the account.

The economics. A farm profits from VOLUME: free-tier abuse, review and follower inflation, accounts
staged for later stuffing. One fake account is indistinguishable from a real one; a thousand share
infrastructure. Attack the costs the farm tried to avoid, cheapest check first.

The facts you get. demo_site/ext/economies.py fills ctx.attrs["signup"] on POST /register and
POST /api/register:

    email, domain   str
    disposable      bool   the domain is on data/disposable_domains.txt
    device          str    the `did` device cookie (the session id when there is none)

and the check runs at `action:register`. Count in Redis with the starter's windowed counter:

    from . import store
    store.Counters(ctx.redis).hit("signup_ip", ctx.ip, window=300)       # registrations from this egress
    store.Counters(ctx.redis).hit("signup_device", device, window=300)   # accounts this device minted

Signals (bands: 40 challenge, 75 block). These are SCORING inputs that add up, not independent bans:

  1. disposable domain                 -> 100 (block)
  2. egress above IP_CAP in the window -> 45  (challenge: an emailed code)
  3. device above DEVICE_CAP           -> 45  (challenge)
  4. both together reach 90            -> block. One alone only asks for proof.

The challenge here is the `otp` type: the store emails a code to the address being registered
(/lab/mailbox/<email>) and the sign-up goes through when the code is entered. A farm does not read
those inboxes at scale; a real person on a shared address does.

Who it hurts. Carrier-grade NAT, campuses and offices put many real first-time customers behind one
egress; privacy browsers make many share one device id. In this lab six phones share one carrier
address, so the egress cap asks three of them for a code. Derive the caps from your real per-IP
registration distribution, never a guess.

Reference: solutions/round4/defenses/account_cluster.py (or `checkpoint.py --round 4 --catch-up`)
"""

from . import store
from .pipeline import Check, Signal

IP_CAP = 3          # registrations per egress per window
DEVICE_CAP = 2      # accounts per device per window
WINDOW_S = 300


def _check(ctx):
    signup = ctx.attrs.get("signup")
    if not signup:
        return None
    # TODO (Round 4): return a list of Signals (they add up), or None.
    #   Signal("signup", "disposable_domain", 100, ...)
    #   Signal("signup", "egress_velocity", 45, ...)   when the egress count is above IP_CAP
    #   Signal("signup", "device_cluster", 45, ...)    when the device count is above DEVICE_CAP
    #   For a challenge band score, also return the verdict's type: Verdict("challenge", challenge="otp", signals=...)
    return None


CHECK = Check("account_cluster", _check, phases=("action:register",))
