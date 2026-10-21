"""
Round 1 reference: account and profile rules (catches the farm, tier A).

A farm account is new when it starts messaging, fans out to strangers in a burst, and either
shares its photo with other accounts or signed up from a hosting or VPN network. Each condition
alone has a cohort it would wreck:
  * new + burst fan-out alone flags the trail-festival newcomers (they message everyone they met);
  * photo reuse that counts the community's default avatars flags everyone who never uploaded one;
  * hosting/VPN egress alone flags the privacy-minded members.
So the rule requires all three families at once, and the photo count skips default avatars.

    python solutions/round1_profile.py            # writes out/reference/suspects_r1.csv and scores it
"""
import _ref
import trailmates as tm

NEW_DAYS = 7          # account age when it first messages a stranger
BURST = 15            # first contacts inside any 48 hours
PHOTO_REUSE = 3       # accounts sharing the same uploaded (non-default) photo


def detect(feats=None):
    feats = feats or tm.member_features()
    out = {}
    for mid, f in feats.items():
        age = f["age_at_first_outbound_days"]
        if age is None or age > NEW_DAYS or f["fanout_48h"] < BURST:
            continue
        infra = f["photo_reuse"] >= PHOTO_REUSE or f["egress"] in ("hosting", "vpn")
        if infra:
            out[mid] = 1.0 + f["fanout_48h"] / 100 + (f["photo_reuse"] >= PHOTO_REUSE) * 0.5
    return out


if __name__ == "__main__":
    p = tm.write_suspects(_ref.path("suspects_r1.csv"), detect())
    _ref.score([p])
