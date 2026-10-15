"""Round 2 defense [STUDENT FILE] — enforce the policy on crawlers you can name.

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

TODO (Round 2): evaluate() below; _check() is given.
Fell behind? python tools/checkpoint.py --round 2 --catch-up
"""

from __future__ import annotations

from . import bot_identity, crawl_policy
from .pipeline import Check, Signal, Verdict


def refuse(reason: str, score: int = 80) -> Verdict:
    """A hard 403 with the reason in the decision log (never in the response)."""
    return Verdict("block", score, (Signal("enforce", "refused", score, reason[:160]),))


def evaluate(ident, rule, disallowed: bool):
    """TODO (Round 2): turn the policy into refusals for crawlers you can name.

    ident has .operator (declared token or ""), .verified, .how and .purpose; `rule` is the policy
    for that purpose ("allow" | "deny" | "licensed", or None for an undeclared client); `disallowed`
    says whether this path is Disallowed for it.
      * no operator        -> None  (undeclared client: nothing to enforce against)
      * declared, unverified -> refuse(...)  an identity you cannot verify you cannot trust, bill
                              or complain about
      * rule == "deny"     -> refuse(...)
      * disallowed         -> refuse(...)  it ignored Disallow
      * otherwise          -> None
    Until then everyone is served, and Round 2's ignoring crawler reads it all.
    """
    return None


def _check(ctx):
    if crawl_policy.exempt(ctx.path):
        return None
    ident = bot_identity.identify(ctx)
    rule = crawl_policy.effective_rules(ctx.level).get(ident.purpose) if ident.operator else None
    return evaluate(ident, rule, crawl_policy.is_disallowed(rule, ctx.path))


CHECK = Check("enforce", _check)
