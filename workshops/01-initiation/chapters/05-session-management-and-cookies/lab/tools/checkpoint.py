"""
Round checkpoint for Chapter 5 (Session Management & Cookies). Declares the rounds and
hands over to checkpoint_core.

    python tools/checkpoint.py --round 1              # set level 1, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attacks against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 4 --catch-up   # install solutions/round1..4 first
    python tools/checkpoint.py --all --markdown       # every round (the reference table)

Each round measures two numbers: how many vouchers the bot turned one unlock into, and which of
the 40 shoppers the defense stopped. The shoppers run the `promo` scenario (tools/personas_ch5.py):
land, unlock, redeem, with one phone that redeems from a second address. A round lists the personas
it is allowed to hurt (`allowed_fp`); that list is the false-positive cost of the layer.

There is no challenge type in this chapter, so a challenge verdict is enforced as a block.

Round 3 ships on purpose with `no_js_cookie` weighted as a block (policy.py), which stops the
`no_js` shopper and FAILs. `--catch-up` installs solutions/round3/policy.py, the blue step that
drops it to "monitor"; then it PASSes. See the README.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch5  # noqa: E402,F401  (registers the `promo` scenario and the js_ok hook)
from checkpoint_core import Round, main  # noqa: E402


def binding_costs_a_browser(board, results, attacks):
    """Round 4's lesson: even when copy-hints wins, every voucher still costs one browser mint."""
    out = attacks.get("mint_copy_hints") or {}
    lpv = out.get("launches_per_voucher")
    return (lpv is not None and lpv >= 1.0), f"copy-hints should still need ~1 browser launch per voucher, got {lpv}"


SOL = ("defenses/ladder.py",)

ROUNDS = {
    1: Round(level=1, description="cookie replay vs server-side state", scenario="promo",
             attacks={"replay": "attacks/round1_cookie_replay.py",
                      "replay_share": "attacks/round1_cookie_replay.py --share"},
             expect={"replay": "blocked", "replay_share": "blocked"},
             allowed_fp=(), solutions=SOL),
    2: Round(level=2, description="session reset vs creation velocity", scenario="promo",
             attacks={"reset": "attacks/round2_session_reset.py",
                      "reset_rotate": "attacks/round2_session_reset.py --rotate"},
             expect={"reset": "partial", "reset_rotate": "full"},
             allowed_fp=(), solutions=SOL),
    3: Round(level=3, description="straight-to-redeem vs session signals", scenario="promo",
             attacks={"straight": "attacks/round3_straight_to_redeem.py",
                      "reimplement_js": "attacks/round3_straight_to_redeem.py --reimplement-js"},
             expect={"straight": "blocked", "reimplement_js": "full"},
             allowed_fp=(), solutions=SOL + ("defenses/policy.py",)),
    4: Round(level=4, description="session minting vs identity binding", scenario="promo",
             attacks={"mint": "attacks/round4_session_mint.py",
                      "mint_copy_hints": "attacks/round4_session_mint.py --copy-hints"},
             expect={"mint": "blocked", "mint_copy_hints": "full"},
             allowed_fp=(), extra_checks=[binding_costs_a_browser], solutions=SOL),
}

if __name__ == "__main__":
    main(ROUNDS)
