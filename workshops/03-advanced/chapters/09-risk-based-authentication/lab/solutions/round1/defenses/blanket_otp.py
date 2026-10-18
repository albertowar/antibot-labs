"""
blanket_otp (Round 1): every correct password must be followed by a code from the account's inbox.

The simplest second factor, and the baseline every risk-based scheme is measured against. It stops
the cheap stealer-log crew cold: they hold the password, not the mailbox.

What it misses: an attacker who holds the inbox too. An infostealer copies every session the
browser holds, webmail included, so the "second" factor often sits in the same stolen log as the
first. And every code is relayable by a phishing page in real time (theory, §9.3): an emailed
code proves access to an inbox, not presence at this store.

Who it hurts: everyone, every time. That is the number Round 2 exists to bring down. It also locks
out, completely, anyone who has lost access to the address on file (the `no_inbox` customers).
"""

from .pipeline import Signal, Verdict

POINTS = 50     # the challenge band


def decide(ctx):
    return Verdict("challenge", challenge="otp",
                   signals=(Signal("stepup", "every_login", POINTS, "blanket second factor"),))
