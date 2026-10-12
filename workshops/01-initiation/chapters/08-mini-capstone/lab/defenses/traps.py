"""
W1 Ch8 — Layer: traps (W1 Ch7).

Three traps a human never springs:
    honeypot_field  an extra form field, moved off-screen, aria-hidden, out of
                    the tab order and autocomplete="off". Humans leave it empty.
    trap_link       a link on the home page that is invisible, aria-hidden,
                    rel="nofollow" AND disallowed in robots.txt. Only a crawler
                    that ignores all four follows it.
    trap_path       /.env, /wp-login.php, /admin/.git/config ... paths that
                    don't exist on this store and that only scanners request.

A hit marks the SESSION for good (flagged_session, 100) and the IP for
policy.TRAP_IP_TTL seconds (flagged_ip, only 20: a CGNAT address is shared
by hundreds of people, and one bot among them must not lock them all out).

Trap hits get a fake success instead of a 403 (ladder.Result.deceive): the
bot believes it bought a hoodie, and it learns nothing about which rule
fired. The scoreboard counts what the SERVER sold, not what the bot believes.

What it catches: generic form fillers and crawlers (wave 2).
What it misses: anything that only touches what is rendered (waves 3-4).
False positives: password managers and browser autofill can fill hidden
fields whose name looks like a real field (email2, phone, address). Name the
trap after something autofill ignores. Try HONEYPOT_FIELD = "phone" on Drop
Day and watch the autofill shopper.

Not used here: the 1x1 "pixel trap". Every real browser loads images, so it
flags humans, not bots.
"""

import policy
from ladder import Signal

TRAP_PATHS = {"/.env", "/wp-login.php", "/admin/.git/config", "/phpmyadmin/"}
TRAP_LINK = "/specials/vip-presale"


def flag(ctx, reason):
    ctx.session.add_flag(reason)
    ctx.redis.set(f"trap:ip:{ctx.ip}", reason, ex=policy.TRAP_IP_TTL)


def check(ctx):
    """Layer entry point (Round 3)."""
    points = policy.TRAP_POINTS
    signals = []

    if ctx.path in TRAP_PATHS:
        flag(ctx, "trap_path")
        signals.append(Signal("traps", "trap_path", points["trap_path"], ctx.path))
    elif ctx.path == TRAP_LINK:
        flag(ctx, "trap_link")
        signals.append(Signal("traps", "trap_link", points["trap_link"], "followed an invisible link"))
    elif ctx.method == "POST" and ctx.form.get(policy.HONEYPOT_FIELD):
        flag(ctx, "honeypot_field")
        signals.append(Signal("traps", "honeypot_field", points["honeypot_field"],
                              f"filled the hidden '{policy.HONEYPOT_FIELD}' field"))
    elif ctx.session.flags():
        signals.append(Signal("traps", "flagged_session", points["flagged_session"],
                              f"session hit {', '.join(ctx.session.flags())} earlier"))

    if not signals and ctx.redis.get(f"trap:ip:{ctx.ip}"):
        signals.append(Signal("traps", "flagged_ip", points["flagged_ip"],
                              "this IP hit a trap recently (shared IPs: keep this low)"))
    return signals
