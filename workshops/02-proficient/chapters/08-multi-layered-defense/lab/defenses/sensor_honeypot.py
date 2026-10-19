"""
Layer: honeypot field (stand-in for W1 Ch7)

The login form carries a `website` input that people never see: it is hidden with CSS,
`aria-hidden` and `tabindex="-1"`, so screen readers and keyboard users skip it too (the slot
template is demo_site/ext/templates/risk/collector.html). Scripts that fill every input fill it.

False positives: a few browser autofill heuristics and form-filler extensions. Rare, but not
zero. Its weight (100) blocks on its own under both the veto chain and the score, so if your
support queue ever shows a real customer caught here, lower the weight to the challenge band
rather than deleting the field.
"""

from . import attempt

LAYER = "honeypot"
SIGNALS = {"honeypot_filled": "hidden trap field was filled"}
FIELD = "website"


def sense(ctx):
    return ["honeypot_filled"] if attempt.field(ctx, FIELD) else []
