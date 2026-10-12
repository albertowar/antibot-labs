"""
Chapter 7 — Responding to a Trap Hit (Section 7.4)

Detecting a bot is half the job. What you do next decides what the attacker
learns, and who else gets hurt.

Levels 1-3 only DETECT. A trapped signup gets a fake success page and is not
saved, and a trapped crawl gets a plausible page. Nothing happens to the
client afterwards.

Level 4 adds a SANCTION: after a hit, the client's later requests are treated
differently for SANCTION_TTL (trap_store.py). Two settings control it:

RESPONSE_MODE
  block       403 on the hit and on everything after it. Cheap and clear, and
              a free oracle: the bot knows instantly which request tripped it.
  fake        Fake success. Nothing is saved. The bot reports success, but a
              bot that checks its work (logging in with the new account) sees
              that the account doesn't exist.
  quarantine  Accept and contain. The account is created but flagged. Login
              works, and its reviews are shown only to their author (a shadow
              ban). The bot can't easily tell it failed. You pay for storage,
              moderation tooling and the risk of quarantining a real person.

  Not here: tarpitting (delaying responses). `time.sleep()` in a sync worker
  ties up YOUR thread for every second the bot waits. Do it at the edge or in
  an async server, or not at all.

SANCTION_KEY
  ip          Sanction the whole IP. Hits every human behind the same CGNAT,
              office NAT or VPN exit (W1 Ch2).
  session     Sanction the session cookie. Real users behind the same IP are
              untouched, but a bot that drops its cookies starts clean. That
              is acceptable: it still has to get past every trap again.
"""

import os

RESPONSE_MODES = ("block", "fake", "quarantine")
SANCTION_KEYS = ("ip", "session")

RESPONSE_MODE = os.environ.get("RESPONSE_MODE", "block")
SANCTION_KEY = os.environ.get("SANCTION_KEY", "ip")

if RESPONSE_MODE not in RESPONSE_MODES:
    raise SystemExit(f"RESPONSE_MODE must be one of {RESPONSE_MODES}")
if SANCTION_KEY not in SANCTION_KEYS:
    raise SystemExit(f"SANCTION_KEY must be one of {SANCTION_KEYS}")


def mode(level):
    """What a trapped or sanctioned request gets at this level."""
    return RESPONSE_MODE if level >= 4 else "detect"


def sanction_target(ip, sid):
    """The (key type, value) a sanction is stored under."""
    return ("ip", ip) if SANCTION_KEY == "ip" else ("sid", sid)


if __name__ == "__main__":
    print(f"RESPONSE_MODE={RESPONSE_MODE} SANCTION_KEY={SANCTION_KEY}")
    for level in range(5):
        print(f"  level {level}: {mode(level)}")
    print("  sanction stored under:", sanction_target("203.0.113.77", "a1b2c3d4"))
