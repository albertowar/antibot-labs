"""
The ladder: which checks run at which DEFENSE_LEVEL. (Pre-wired in this lab: the rounds are the
modules you fill in, not the wiring. A check you have not finished is inert.)

    level 0   request_checks (W1: headers, a loose rate) and the W2 browser stack, both in SHADOW: they
              log what they would have said and never decide. Every agent in this chapter walks past both.
    level 1   agent_policy    declared agents may browse, not buy                        (Round 1)
    level 2   agent_behavior  robotic sessions get the step-up (a challenge, never a block) (Round 2)
    level 3   agent_identity  a Web Bot Auth identity that does not verify is refused;
                              a verified one from a trusted operator is an agent we know  (Round 3)
    level 4   checkout_gate   mandates, step-up for the suspicious and the new, a device cap (Round 4)

Level k is enforced when k <= DEFENSE_LEVEL. All four rule modules act on the drop purchase
(`action:drop_buy`: POST /drop/<sku> and POST /api/buy), where the points add up on the 0-100 scale of
policy.py: under 30 allow, 30-59 the `step_up` challenge, 60 and over block. The principal (human,
declared, verified) and the identity are computed once per request by defenses/principal.py.

Change a module, save, and the store picks it up on the next request (LAB_RELOAD=1).
Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference modules for
rounds 1..N.
"""

from . import agent_behavior, agent_identity, agent_policy, checkout_gate, request_checks, w2_shadow

LADDER = {
    0: [request_checks.CHECK, w2_shadow.CHECK],
    1: [agent_policy.CHECK],
    2: [agent_behavior.CHECK],
    3: [agent_identity.CHECK],
    4: [checkout_gate.CHECK],
}
