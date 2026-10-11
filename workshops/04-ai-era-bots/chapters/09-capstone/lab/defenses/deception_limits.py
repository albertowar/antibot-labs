"""
W4 Ch9 Capstone — L3 deception within limits (YOUR CODE, Round 3)

extractor_traps.decorate(ctx) (GIVEN, W4 Ch5 Round 3) returns the text-layer
traps the catalogue renders inside an off-screen, aria-hidden container:
honeypot records, a canary instruction an obedient extractor stamps on its own
loot, and decoy paragraphs that cost it tokens.

Your W4 Ch8 governance record (section 11) says: decoys go only to sessions you
would otherwise refuse, never to a crawler honouring the reservation, never to
a declared agent that followed the terms, and never read aloud to a person.
This module is where that sentence becomes code.

ctx keys (GIVEN): sid, canary, page, honeypots; would_block (the shadow verdict:
True when crawl governance would refuse this client, or the request score is
already in the challenge band); identity (crawler_identity.Identity); a11y (the
session used the accessibility API). Return the extractor_traps dict or EMPTY.

The stub serves traps to everyone — what most teams ship first, and what the
auditor's card 5 is about. `tools/checkpoint.py --round 3 --catch-up` drops in
the reference.
"""

import extractor_traps

EMPTY = {"hidden_records": [], "canary_note": None, "decoy_paragraphs": []}


def decorate(ctx):
    # TODO (Round 3): serve traps only when ctx["would_block"] is True, and never
    # to a verified honoured crawler or a session using the accessibility API.
    return extractor_traps.decorate(ctx)
