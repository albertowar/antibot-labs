"""
Chapter 4 — Fingerprint Scoring Engine (Section 4.5)

Runs every layer enabled by DEFENSE_LEVEL on a sign-up and adds up points.

    Level 0  no defense (log only)
    Level 1  + render-stack plausibility    (render_stack.py)
    Level 2  + lie detection                (lie_detector.py)
    Level 3  + exact-ID linking             (linking.py)
    Level 4  + fuzzy clustering             (fuzzy_cluster.py)

From level 1 on, a sign-up must also carry a fingerprint collected in the
same session (the collector didn't run → +40). That costs the few users
who block JavaScript, so in production you'd send them to a challenge
(W1 Ch5) rather than a 403.

Thresholds (the same as W1 Ch3's header engine):
    score >= 40  bot         (403)
    score >= 20  suspicious  (logged, allowed through)
    score <  20  clean

`signals` lists the named signals that fired, for the risk engine in
Workshop 2, Chapter 8 and the features in Chapter 7.
"""

import re

from fuzzy_cluster import score_cluster
from lie_detector import score_lies
from linking import score_linking
from render_stack import score_render_stack

BOT_THRESHOLD = 40
SUSPICIOUS_THRESHOLD = 20
NO_FINGERPRINT_POINTS = 40
SIGNAL_NAMES = re.compile(r"\b(fingerprint_mismatch|fingerprint_linked|fingerprint_cluster)\b")


def get_verdict(score):
    if score >= BOT_THRESHOLD:
        return "bot"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def evaluate(fp, headers, level, count_accounts=lambda _sid: 0, recent_cores=lambda: [],
             link_mode="rarity"):
    """
    Score one sign-up.

    fp              the fingerprint payload stored for this session, or None
    headers         headers of the request that delivered the payload
    count_accounts  callable for L3 (stable_id -> accounts today)
    recent_cores    callable for L4 (-> core components of today's accounts)

    Returns (score, reasons, verdict, signals). Reasons are tagged by layer.
    """
    if level >= 1 and fp is None:
        reasons = ["[L1] No fingerprint for this session (the collector never ran)"]
        return NO_FINGERPRINT_POINTS, reasons, get_verdict(NO_FINGERPRINT_POINTS), ["no_fingerprint"]
    layers = [
        (1, "L1", lambda: score_render_stack(fp)),
        (2, "L2", lambda: score_lies(fp, headers)),
        (3, "L3", lambda: score_linking(fp, count_accounts, link_mode)),
        (4, "L4", lambda: score_cluster(fp, recent_cores, link_mode)),
    ]
    score, reasons = 0, []
    for min_level, tag, check in layers:
        if level < min_level:
            continue
        points, why = check()
        score += points
        reasons.extend(f"[{tag}] {r}" for r in why)
    signals = sorted({m.group(1) for r in reasons for m in SIGNAL_NAMES.finditer(r)})
    if any(r.startswith("[L1]") and not r.startswith("[L1] note") for r in reasons):
        signals.insert(0, "render_stack")
    return score, reasons, get_verdict(score), signals


if __name__ == '__main__':
    headless = {
        "nav": {"userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "HeadlessChrome/153.0.8010.12 Safari/537.36", "platform": "Linux x86_64"},
        "webgl": {"supported": True, "unmaskedRenderer":
                  "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"},
        "canvas": {"supported": True}, "audio": {"supported": True}, "voices": {"count": 0},
    }
    for level in range(5):
        score, reasons, verdict, signals = evaluate(headless, {}, level)
        print(f"Level {level}: score={score} verdict={verdict} signals={signals}")
        for r in reasons:
            print(f"  - {r}")
