"""Round 2 defense [STUDENT FILE] — enforce the policy on crawlers you can name.

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
    """TODO (Round 2): turn the policy into refusals for crawlers you can name.

    ctx["identity"] has .operator (declared token or None), .verified, .how and
    .purpose; ctx["rule"] is the policy for that purpose; ctx["disallowed"] says
    whether this path is Disallowed for it; ctx["violations"] counts earlier ones.
      * no operator               -> allow("undeclared client: nothing to enforce against")
      * declared but not verified -> block(...)  an identity you cannot verify you
                                     cannot trust, bill, or complain about
      * rule == "deny"            -> block(...)
      * ctx["disallowed"]         -> block(...)  it ignored Disallow
      * otherwise                 -> allow(...)
    Until then everyone is allowed, and Round 2's ignoring crawler reads it all.
    """
    return allow("TODO (Round 2): policy published, nothing enforced yet")
