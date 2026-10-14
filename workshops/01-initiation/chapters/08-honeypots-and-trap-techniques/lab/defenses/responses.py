"""
responses (Round 4): what you do when a trap fires, and what happens to the client afterwards.

Detecting a bot is half the job. What you do next decides what the attacker learns, and who else
gets hurt. Two settings in policy.py control it:

TRAP_RESPONSE_MODE
  block       403 on the hit and on everything after it. Cheap and clear, and a free oracle: the bot
              knows at once which request tripped it (here the X-Lab-Signals header even names the
              trap; with LAB_HEADERS=0 it only sees the 403).
  fake        A signup or review is answered like a real one and thrown away. A bot that checks its
              work (logs in with the new account) sees that nothing exists.
  quarantine  Accept and contain. The account is created but flagged, and its reviews are shown only
              to their author (a shadow ban). The bot cannot easily tell it failed. You pay for
              storage, moderation tooling, and the risk of quarantining a real person.

  Not here: tarpitting. `time.sleep()` in a synchronous worker ties up YOUR thread for every second
  the bot waits. Do it at the edge or in an async server, or not at all.

TRAP_SANCTION_KEY
  ip          Sanction the whole address. Hits every human behind the same CGNAT, office NAT or VPN
              exit (Chapter 3).
  session     Sanction the session cookie. Real users on the same IP are untouched, but a bot that
              drops its cookies starts clean. That is acceptable: it still has to get past every
              trap again.

Below level 4 nothing is sanctioned: `on_hit` only answers the hit itself (a fake success for a form
trap, a plain monitor signal for a crawl trap) and no state is kept. At level 4 a hit also writes a
sanction (a Redis key with a TTL, `policy.SANCTION_TTL`), and this module's check applies the mode to
the client's LATER requests.

Trade-offs:
  - Sanctions expire. A permanent block list grows forever, and the addresses on it get reassigned to
    real customers. Fifteen minutes is enough to make a bot start over, and short enough that a false
    positive heals itself. A new hit re-arms the key; ordinary requests do not extend it.
  - `block` and `fake` are visible to the person caught. `quarantine` is not, which is exactly what
    makes it the worst kind of false positive: nobody complains. Sample what you quarantine.
  - The sanction lookup is one Redis GET per request. Compare the level 3 and level 4 gate times.
"""

from . import policy
from .pipeline import Check, Signal, Verdict

MODES = ("block", "fake", "quarantine")
KEYS = ("ip", "session")

# Requests whose answer a "fake" sanction can forge: the two writes a bot abuses.
FAKEABLE = ("/register", "/review/")


def mode(level):
    """What a trapped or sanctioned request gets at this level."""
    return policy.TRAP_RESPONSE_MODE if level >= 4 else "detect"


def _key(ctx):
    """The (kind, value) a sanction is stored under."""
    if policy.TRAP_SANCTION_KEY == "ip":
        return "ip", ctx.ip
    return "sid", ctx.session.sid


def _redis_key(kind, value):
    return f"lab:traps:sanction:{kind}:{value}"        # lab: prefix, so /lab/reset wipes it


def sanction(ctx, trap):
    """Sanction the client for SANCTION_TTL seconds. Re-armed by every new hit."""
    ctx.redis.set(_redis_key(*_key(ctx)), trap, ex=policy.SANCTION_TTL)


def sanctioned(ctx):
    """The trap that earned the sanction, or None."""
    return ctx.redis.get(_redis_key(*_key(ctx)))


def _fakeable(ctx):
    return ctx.method == "POST" and ctx.path.startswith(FAKEABLE)


def _monitor(ctx, signal):
    """A logged-and-served signal. Points add up across checks, so only the first one in a request counts:
    two traps at 30 points each would otherwise add up to a block."""
    if ctx.attrs.get("trap_scored"):
        return None
    ctx.attrs["trap_scored"] = True
    return [signal]


def on_hit(ctx, layer, trap, detail="", form=False):
    """
    Called by a trap check the moment it fires. Returns what the check should return.

    `form` says the trap sits on a write (signup): there a hit is answered with a fake success. A
    crawl trap is only logged, so the crawler still gets a plausible page (detection is not
    prevention). At level 4 the hit also sanctions the client and the mode applies to the hit itself.
    """
    ctx.note(trap=trap)
    m = mode(ctx.level)
    if ctx.level >= 4:
        sanction(ctx, trap)
    if m == "block":
        return Verdict("block", signals=(Signal(layer, trap, policy.TRAP_HARD_POINTS, detail),))
    if form and m in ("detect", "fake"):
        return Verdict("deceive", signals=(Signal(layer, trap, policy.TRAP_HARD_POINTS, detail),))
    if form and m == "quarantine":
        ctx.attrs["quarantine"] = trap                  # the ext flags the account and parks its reviews
    return _monitor(ctx, Signal(layer, trap, policy.TRAP_MONITOR_POINTS, detail))


def _check(ctx):
    # TODO (Round 4): on_hit() above already answered the HIT itself and wrote the sanction. This check
    # answers the client's LATER requests. sanctioned(ctx) returns the trap that earned the sanction, or
    # None. Then apply policy.TRAP_RESPONSE_MODE:
    #   block       return Verdict("block", ...)
    #   fake        a Verdict("deceive", ...) for POST /register and POST /review/* (see _fakeable)
    #   quarantine  set ctx.attrs["quarantine"] so the ext parks the account and its reviews
    # and return one monitor Signal through _monitor() for the requests that are served. Until you write
    # it, the hit is answered but the next request from the same client is not.
    return None


CHECK = Check("responses", _check)


if __name__ == "__main__":
    print(f"TRAP_RESPONSE_MODE={policy.TRAP_RESPONSE_MODE} TRAP_SANCTION_KEY={policy.TRAP_SANCTION_KEY}")
    for level in range(5):
        print(f"  level {level}: {mode(level)}")
