"""Round 2 defense (REFERENCE SOLUTION) — enforce the policy on crawlers you can name.

Round 1 showed that a published preference governs only the crawlers that read
it. Enforcement turns the preference into a refusal, but it can only key on an
identity it trusts (defenses/bot_identity.py, from W4 Ch1-2):

  * declared crawler, verified, purpose rule "deny"  -> BLOCK (robots says Disallow: /)
  * declared crawler, verified, inside a trap path   -> BLOCK (ignored Disallow)
  * declared crawler, NOT verified                   -> BLOCK: a UA you cannot
    verify is a UA you cannot trust, bill, or complain to its operator about
  * everything else                                   -> ALLOW

The paradox students should see in the numbers: the honest crawler that
announces itself is the one that gets refused, while Round 2's stealth crawler
(Chrome UA, residential egress) walks in. That is not a bug in this module; it
is the limit of identity-based governance, and why the deterrence (Round 3) and
W2's detection stack exist.

False positives, named: anything keyed on "unfamiliar UA" instead of "declared
crawler" would hit text browsers, feed readers, accessibility tools and link
previewers (the lab's reader cohort). This module never looks at ua_class.
"""

from __future__ import annotations

from store import allow, block, Decision


def evaluate(ctx) -> Decision:
    ident = ctx["identity"]
    if not ident.operator:
        return allow("undeclared client: nothing to enforce against")
    if not ident.verified:
        return block(f"declared {ident.operator} but unverified ({ident.how}): can't trust, can't bill",
                     score=80.0)
    if ctx["rule"] == "deny":
        return block(f"policy denies {ident.purpose} for verified {ident.operator}", score=60.0)
    if ctx["disallowed"]:
        return block(f"verified {ident.operator} in a Disallowed path (violation #{ctx['violations'] + 1})",
                     score=70.0)
    return allow(f"verified {ident.operator} ({ident.purpose}) within policy")
