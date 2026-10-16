"""
The ladder: the capstone's stack, one layer per DEFENSE_LEVEL.

    0  W1 request checks (always on) + the end-of-W2 stack in permanent shadow
    1  (ext) crawl governance on content paths: allow / 402 / charged / maze / block
    2  agent governance at the checkout: the Ch8 policy, live
    3  (ext) deception within limits + the LLM guard on /summary and /assist
    4  the human-approved rules at the checkout + the oracle guard on every reply

Levels 1 and 3 act on content RESPONSES (a 402, a maze page, a shaped reply),
which a Check cannot express: they live in demo_site/ext/capstone_store.py and
read ctx.level themselves — the W4 Ch3/Ch5 pattern. Run with LAB_SHADOW=1 to
see every layer above the current level in X-Lab-Shadow (Round 0's lesson).

Because LADDER[0] is a permanent baseline, the contract test runs with
LAB_SMOKE=1 (tools/verify.py --smoke sets it) and sees the bare store.
"""

from . import capstone

LADDER = {
    0: [capstone.REQUEST_HEADERS, capstone.EGRESS_RATE, capstone.W2_SHADOW],
    2: [capstone.AGENT_GOVERNANCE],
    4: [capstone.APPROVED_RULES],
}
