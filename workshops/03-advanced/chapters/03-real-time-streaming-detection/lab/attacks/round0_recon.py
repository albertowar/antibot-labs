"""
Round 0 attack: the same micro-burst, with nothing reading the stream.

Round 0 is the recon round. The store writes every request to the event stream (so the log fills),
but at level 0 no detector reads it: scoring would happen when the session is closed out, or in
a batch job, well after the attacker has what they came for. The burst is identical to Round 1's;
only the defense changes between the two rounds. That gap (about ten seconds here, hours in a
nightly batch) is what this chapter closes.

    python attacks/round0_recon.py
"""

from _common import finish
from round1_microburst import run

if __name__ == "__main__":
    finish(run())
