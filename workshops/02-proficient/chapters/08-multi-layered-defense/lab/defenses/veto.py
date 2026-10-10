"""
Chapter 8, Round 1: The veto chain (DEFENSE_LEVEL = 1)

This is how most stacks grow: every chapter's defense was added with its own
"block if" rule, and any one of them can reject the request. Each layer was
tuned on its own data, so each one looks fine in isolation.

Two problems appear the moment you run them together:

1. False positives add up. Every layer blocks the slice of real users that
   looks odd *to that layer*: VPN users at the network layer,
   keyboard-only users at the behaviour layer, privacy browsers at the
   fingerprint layer. The slices barely overlap, so the union is roughly
   the sum: 1 - prod(1 - fp_i).
2. Detection does not add up. A bot that keeps every layer just under its
   own line sails through, however many weak signals it shows at once.
   That is Round 1's attack.

The points are the same WEIGHTS that policy.py uses, summed per layer.
"""

from policy import WEIGHTS

# Each layer blocks when its own points reach this line
VETO_AT = {
    "net": 25,
    "headers": 30,
    "tls": 40,
    "velocity": 30,
    "honeypot": 100,
    "automation": 40,
    "fingerprint": 15,
    "behavior": 25,
}


def layer_points(signals_by_layer):
    return {layer: sum(WEIGHTS.get(s, 0) for s in signals)
            for layer, signals in signals_by_layer.items()}


def decide(signals_by_layer):
    """Return ("block", layer) for the first layer over its line, else ("allow", None)."""
    for layer, points in layer_points(signals_by_layer).items():
        if layer in VETO_AT and points >= VETO_AT[layer]:
            return "block", layer
    return "allow", None
