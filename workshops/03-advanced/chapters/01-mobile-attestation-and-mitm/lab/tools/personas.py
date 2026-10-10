"""
W3 Ch1 — Legitimate mobile customers (the people a defense must not block)

Each persona is a real customer running the genuine app on a real device. Most
are on certified phones that earn strong hardware-backed integrity. A few are
the users who make device attestation hard:

    rooted            a developer / power user with an unlocked bootloader
    graphene          a privacy-conscious user on a de-Googled custom ROM,
                      app sideloaded (no Play recognition)
    old-uncertified   a cheap older Android that never passed Play certification

These last ones return weak integrity for honest reasons. Round 4's defense has
to stop the emulator FARM without turning these customers away. Watch them in
the checkpoint: they are the false-positive bill.
"""

PASSWORD = "Customer-pass-1"
ADDR = "12 Maple Ave, Springfield IL 62704"

LEGIT_USERS = [
    # Each customer is on their own home network (a distinct residential IP).
    # Real CGNAT would cluster many of them behind one IP — a false-positive risk
    # for the Round 4 per-egress farm signal, discussed in the chapter.
    {"email": "amara@mail.example", "device": "pixel8", "persona": "flagship-android", "egress": "203.0.113.101"},
    {"email": "ben@mail.example", "device": "iphone15", "persona": "iphone", "egress": "203.0.113.102"},
    {"email": "chen@mail.example", "device": "pixel8", "persona": "flagship-android", "egress": "203.0.113.103"},
    {"email": "dalia@mail.example", "device": "iphone15", "persona": "iphone", "egress": "203.0.113.104"},
    {"email": "evan@mail.example", "device": "pixel6-old", "persona": "older-certified", "egress": "203.0.113.105"},
    {"email": "farah@mail.example", "device": "pixel8", "persona": "flagship-android", "egress": "203.0.113.106"},
    {"email": "gita@mail.example", "device": "iphone15", "persona": "iphone", "egress": "203.0.113.107"},
    {"email": "hugo@mail.example", "device": "pixel6-old", "persona": "older-certified", "egress": "203.0.113.108"},
    {"email": "ivy@mail.example", "device": "rooted", "persona": "rooted-power-user", "egress": "203.0.113.109"},  # false-positive cohort
    {"email": "jonas@mail.example", "device": "graphene", "persona": "grapheneos-privacy", "egress": "203.0.113.110"},  # false-positive cohort
    {"email": "kira@mail.example", "device": "graphene", "persona": "grapheneos-privacy", "egress": "203.0.113.111"},  # false-positive cohort
    {"email": "liam@mail.example", "device": "old-uncertified", "persona": "cheap-old-android", "egress": "203.0.113.112"},  # false-positive cohort
]


def accounts():
    return [{**u, "password": PASSWORD, "address": ADDR} for u in LEGIT_USERS]
