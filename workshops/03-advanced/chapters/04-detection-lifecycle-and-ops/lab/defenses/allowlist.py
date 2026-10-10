"""
Chapter 4 (W3): Allowlists are a measured cost, not a free pass

Every production stack carries exemptions, and every exemption is a hole
the next attacker looks for. The lab ships exactly one, and uses it to
measure something:

    The known-good cohort. Synthetic monitors and QA accounts that present
    KNOWN_GOOD_TOKEN in X-Known-Good. They are scored by every layer like
    anyone else, logged with known_good=true, and never enforced against.
    The signals that fire on them are the only live false-positive rate a
    defender can measure without labels (metrics.known_good_signal_total).

Why it is honest: the cohort is scored, so a layer that would have hurt
them is caught, and it is exempt, so your own monitoring never pages you
because your bot defense blocked your uptime check.

Why it is dangerous: the token is a password to your front door. Rotate it,
bind it to source ranges, and alert when it arrives from anywhere else.
Bonus challenge: send it from the Round 4 attacker and watch.

Why it is biased: monitors run current Chrome from a fixed address. They
will never tell you what the stack does to a VPN user on an old phone. The
cohort measures the floor of your false-positive rate, never its height.

The six archetypes the chapter discusses (corporate egress, accessibility
tools, VPN users, monitoring probes, API integrators, privacy extensions)
are documented in chapter_04_content.md §4.7, with the exemption each one
usually gets and what that exemption costs.
"""

import hmac
import os

KNOWN_GOOD_TOKEN = os.environ.get("KNOWN_GOOD_TOKEN", "lab-monitor-7f3a")


def is_known_good(headers):
    token = headers.get("X-Known-Good", "")
    return bool(token) and hmac.compare_digest(token, KNOWN_GOOD_TOKEN)


def enforce(decision, known_good):
    """Return the action to take. Known-good traffic is scored but never acted on."""
    if known_good and decision.action != "allow":
        return "allow", f"known_good: would have been {decision.action}"
    return decision.action, None
