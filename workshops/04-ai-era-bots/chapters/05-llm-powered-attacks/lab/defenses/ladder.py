"""
The ladder: which checks run at which DEFENSE_LEVEL. (Pre-wired in this lab: the rounds are the modules you
fill in, not the wiring. A check you have not finished is inert.)

    level 0   what the store shipped with: honeypot (a SKU nobody is shown). Nothing else, so the contract's
              smoke test (a four-letter review is published) passes at level 0.
    level 1   content (pre-written: duplicates, templates, links, one-liners are held) and review_signals,
              Round 1: who is reviewing (account age, purchase, device and egress velocity)
    level 2   challenge_policy  Round 2: who gets a puzzle, what it costs, what a solve is worth
    level 3   extractor_traps   Round 3: text-only honeypots, a canary and decoys for LLM extractors
    level 4   llm_guard         Round 4: the guard around the store's own LLM features

Level k is enforced when k <= DEFENSE_LEVEL. The verdict set is closed (allow, monitor, challenge, block,
rate_limit, deceive): a review that is *held* for moderation is not a verdict, so the checks record it in
`ctx.attrs` and `demo_site/ext/llm_surfaces.py` parks it (contract 1.6's `hooks.on_action`).

Change a module, save, and the store picks it up on the next request (LAB_RELOAD=1).
Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference modules for rounds 1..N.
"""

from . import challenge_policy, content_heuristics, extractor_traps, honeypot_sku, llm_guard, review_signals

LADDER = {
    0: [honeypot_sku.CHECK],
    1: [content_heuristics.CHECK, review_signals.CHECK],
    2: [challenge_policy.CHECK],
    3: [extractor_traps.CHECK],
    4: [llm_guard.CHECK],
}
