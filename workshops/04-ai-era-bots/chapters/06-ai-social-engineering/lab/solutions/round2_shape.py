"""
Round 2 reference: conversation shape (catches the LLM crew, tier B), added to Round 1.

The crew's accounts are aged, their photos and wording unique, so Round 1 sees nothing. What the
model does not change is the operation around it: one shift of operators works every persona, so
every message falls inside the same ten UTC hours, seven days a week; each persona opens many
threads with strangers and nobody ever opens one with it; and the conversation is moved to
another app within days. Each of those alone describes an honest cohort:
  * office-hours concentration and huge fan-out are the guides (but they never ask anyone to leave);
  * outbound fan-out with an early "text me" is a gear seller (but sellers keep personal hours).
The rule requires the shift shape, outbound fan-out and early off-platform moves together.

    python solutions/round2_shape.py             # writes out/reference/suspects_r2.csv (Round 1 + Round 2)
"""
import _ref
import round1_profile
import trailmates as tm

OUTBOUND = 10         # threads this account opened with someone
SHIFT = 0.95          # share of its messages in its busiest ten contiguous UTC hours
EARLY_OFF = 0.15      # share of its opened threads it moved off-platform within 7 days


def detect(feats=None):
    feats = feats or tm.member_features()
    out = dict(round1_profile.detect(feats))
    for mid, f in feats.items():
        if mid in out:
            continue
        if f["outbound_first"] >= OUTBOUND and f["hour_concentration"] >= SHIFT and f["early_offplatform_rate"] >= EARLY_OFF:
            out[mid] = 1.0 + f["early_offplatform_rate"]
    return out


if __name__ == "__main__":
    p = tm.write_suspects(_ref.path("suspects_r2.csv"), detect())
    _ref.score([p, "--prev", _ref.path("suspects_r1.csv")] if __import__("os").path.exists(_ref.path("suspects_r1.csv")) else [p])
