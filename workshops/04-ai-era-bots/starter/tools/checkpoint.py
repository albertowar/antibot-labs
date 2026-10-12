"""
Round checkpoint for this lab. Declares the rounds and hands over to checkpoint_core.

The W4 starter has no rounds: Round 0 only proves that the baseline hurts no
shopper. A chapter lab fills ROUNDS in (see checkpoint_core.Round).

    python tools/checkpoint.py --round 0
"""

from checkpoint_core import Round, main

ROUNDS = {
    0: Round(level=0, description="bare store: no defenses, every shopper buys", scenario="browse", bot_success_max=1.0),
}

if __name__ == "__main__":
    main(ROUNDS)
