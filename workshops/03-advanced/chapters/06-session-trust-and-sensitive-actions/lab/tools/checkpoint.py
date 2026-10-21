"""
Round checkpoint for W3 Ch6 (Session Trust & Sensitive Actions). Declares the rounds and hands over to
checkpoint_core.

Every round runs the 80 account holders of tools/personas_ch6.py (sign in, then do one thing: buy, move,
redeem a gift card, replace a card, change the password or the email) next to the starter's 40 shoppers,
at the round's level. What it judges is the defender's side of the bill:

    friction   account holders who met a step-up or a hold at their goal, against policy.FRICTION_BUDGET
               (printed every round; Round 1's sudo mode is reported, not judged)
    hurt       goal_missed / stuck_on_challenge / blocked, outside the round's allowed_fp
    delayed    202s (a held change or order), reported with the lab-hour delay each one waited

The attacker side (the three crews of demo_site/ext/session_world.py replaying what a stealer log or a
hijacked inbox gave them) is not in this checkpoint yet: see the chapter's TODO.md. The rounds name the crew
each defense is aimed at, so the attack scripts or crew profiles plug in as `attacks=` without changing
anything else.

    python tools/checkpoint.py --round 2             # check round 2
    python tools/checkpoint.py --round 2 --catch-up  # install solutions/round2 (and earlier) first
    python tools/checkpoint.py --restore             # put your own files back
"""

from checkpoint_core import Round, main

import personas_ch6 as P
from defenses import policy


def friction(judged=True):
    """The friction line, printed every round. Round 1 reports it without judging: sudo mode asking every
    account holder with a sensitive goal for the password is the cost the later rounds exist to cut."""
    def check(board, results, *_):
        k, n = P.friction(results)
        budget = policy.FRICTION_BUDGET
        prompts = {}
        for r in results:
            if r.get("persona") in P.PERSONAS:
                for t in r.get("prompts") or ():
                    prompts[t] = prompts.get(t, 0) + 1
        delays = P.delays(results)
        median = delays[len(delays) // 2] if delays else 0
        msg = (f"friction {k}/{n} ({k / max(n, 1):.0%}, budget {budget:.0%}{'' if judged else ', not judged'}); "
               f"step-ups {dict(sorted(prompts.items()))}; delayed {len(delays)}, median {median} lab h")
        print(msg)
        return (k <= budget * n) or not judged, msg
    return check


COMMON = dict(scenario="ch6", people=P.people, threads=1)
JUDGED = dict(COMMON, extra_checks=[friction()])

ROUNDS = {
    0: Round(level=0, description="Chapter 5's login stack; nothing guards the session after it", **JUDGED),
    1: Round(level=1, description="sudo mode: password re-auth on every weighted action (aimed at the session-cookie crew)",
             solutions=("defenses/sudo_reauth.py",), extra_checks=[friction(judged=False)], **COMMON),
    2: Round(level=2, description="session trust + action weights + restricted session + emailed code "
                                   "(aimed at the remembered-device crew)",
             allowed_fp=("no_inbox",), solutions=("defenses/session_trust.py",), **JUDGED),
    3: Round(level=3, description="step-up by possession: known device or SMS, KBA when neither is on file "
                                   "(aimed at the webmail crew)",
             allowed_fp=("no_inbox", "rotator", "shared_family"), solutions=("defenses/stepup_channels.py",),
             **JUDGED),
    4: Round(level=4, description="KBA demoted to a signal; cooling-off + notify; low-trust orders to new addresses held",
             solutions=("defenses/change_hold.py",), **JUDGED),
}

if __name__ == "__main__":
    main(ROUNDS)
