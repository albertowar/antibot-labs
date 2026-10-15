"""Round 2 defense [REFERENCE SOLUTION] — enforce the policy on crawlers you can name.

Round 1 showed that a published preference governs only the crawlers that read it. Enforcement
turns the preference into a refusal, but it can only key on an identity it trusts
(defenses/bot_identity.py, which verifies Web Bot Auth signatures as W4 Ch2 built it):

  * declared crawler, verified, purpose rule "deny"  -> BLOCK (robots says Disallow: /)
  * declared crawler, verified, inside a trap path   -> BLOCK (ignored Disallow)
  * declared crawler, NOT verified                   -> BLOCK: a UA you cannot verify is a UA you
    cannot trust, bill, or complain to its operator about
  * everything else                                  -> ALLOW

The paradox you should see in the numbers: the honest crawler that announces itself is the one that
gets refused, while Round 2's stealth crawler (Chrome UA, residential egress) walks in. That is not
a bug in this module; it is the limit of identity-based governance, and why the deterrence (Round 3)
and W2's detection stack exist.

False positives, named: anything keyed on "unfamiliar UA" instead of "declared crawler" would hit
text browsers, feed readers, accessibility tools and link previewers (the lab's reader cohort; note
that Lynx's `libwww` token makes `ctx.ua.is_library` true). This module never looks at the UA
family. The policy documents (robots.txt, license.xml, llms.txt) are exempt: a crawler that cannot
read them cannot obey them.

Done in this file: evaluate(). _check() was given.
"""

from __future__ import annotations

from . import bot_identity, crawl_policy
from .pipeline import Check, Signal, Verdict


def refuse(reason: str, score: int = 80) -> Verdict:
    """A hard 403 with the reason in the decision log (never in the response)."""
    return Verdict("block", score, (Signal("enforce", "refused", score, reason[:160]),))


def evaluate(ident, rule, disallowed: bool):
    """Turn the policy into refusals for crawlers you can name."""
    if not ident.operator:
        return None                                   # undeclared client: nothing to enforce against
    if not ident.verified:
        return refuse(f"declared {ident.operator} but unverified ({ident.how}): can't trust, can't bill", 80)
    if rule == "deny":
        return refuse(f"policy denies {ident.purpose} for verified {ident.operator}", 60)
    if disallowed:
        return refuse(f"verified {ident.operator} in a Disallowed path", 70)
    return None


def _check(ctx):
    if crawl_policy.exempt(ctx.path):
        return None
    ident = bot_identity.identify(ctx)
    rule = crawl_policy.effective_rules(ctx.level).get(ident.purpose) if ident.operator else None
    return evaluate(ident, rule, crawl_policy.is_disallowed(rule, ctx.path))


CHECK = Check("enforce", _check)
