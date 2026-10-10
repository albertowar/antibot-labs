"""
Round 0 attack — the same burst, with no streaming detector running

Round 0 is the recon round. You run the micro-burst from Round 1 against the
end-of-W2 posture, where scoring happens at the end of a session (or in a batch
job), not on the stream. The burst completes in about ten seconds; the
session-level verdict arrives when the session is closed out, well after the
attacker has what they came for. That is the latency gap this chapter closes.

The events are identical to Round 1 — only the defense changes between the two
rounds — so this script simply reuses the Round 1 generator.

    python attacks/round0_recon.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in ("attacks", "demo_site"):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), _d))

from round1_microburst import generate  # noqa: E402  (re-exported for checkpoint)

if __name__ == "__main__":
    from _common import deliver
    events = generate()
    deliver(events, f"recon: wrote {len(events)} events. With no streaming detector "
                    f"(L0), nothing scores them until the session closes.")
