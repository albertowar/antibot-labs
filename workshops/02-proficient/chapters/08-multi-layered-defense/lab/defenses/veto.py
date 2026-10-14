"""
Round 1: The veto chain (DEFENSE_LEVEL = 1)

This is how most stacks grow: every chapter's defense was added with its own "block if" rule, and
any one of them can reject the request. Each layer was tuned on its own data, so each one looks
fine in isolation.

Two problems appear the moment you run them together:

1. False positives add up. Every layer blocks the slice of real users that looks odd *to that
   layer*: VPN users at the network layer, keyboard-only users at the behaviour layer, privacy
   browsers at the fingerprint layer. The slices barely overlap, so the union is roughly the sum:
   1 - prod(1 - fp_i).
2. Detection does not add up. A bot that keeps every layer just under its own line sails through,
   however many weak signals it shows at once. That is Round 1's attack.

The points are the same WEIGHTS that policy.py uses, summed per layer. policy.decide() calls
`blocking_layer()` at level 1 and ignores the score.
"""

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


def layer_points(signals):
    """{layer: points} for a list of Signals (or (layer, points) pairs)."""
    out = {}
    for s in signals:
        layer, points = (s.layer, s.points) if hasattr(s, "layer") else s
        out[layer] = out.get(layer, 0) + points
    return out


def blocking_layer(signals):
    """The first layer over its own line, or None. Layers in VETO_AT order, cheapest first."""
    points = layer_points(signals)
    for layer, line in VETO_AT.items():
        if points.get(layer, 0) >= line:
            return layer
    return None
