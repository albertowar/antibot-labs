"""
Chapter 5 — TLS & network scoring engine (Section 5.3)

Runs every layer enabled by DEFENSE_LEVEL and adds up the points, like the
W1 Ch3 header engine.

    Level 0  no defense (log fingerprints only)
    Level 1  + edge check and JA4 library denylist   (ja4_denylist.py)
    Level 2  + UA ↔ TLS family consistency            (tls_family.py)
    Level 3  + HTTP/2 fingerprint ↔ TLS family        (h2_fingerprint.py)
    Level 4  + JS engine proof for browser TLS        (browser_proof.py)

Thresholds:
    score >= 40  bot         (403)
    score >= 20  suspicious  (logged, allowed through)
    score <  20  clean

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the
reference versions from solutions/roundN/defenses/ over these files.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))

from browser_proof import score_browser_proof  # noqa: E402
from h2_fingerprint import score_h2  # noqa: E402
from ja4_denylist import score_denylist  # noqa: E402
from tls_family import claimed_engine, score_tls_family, tls_engine  # noqa: E402

BOT_THRESHOLD = 40
SUSPICIOUS_THRESHOLD = 20


def get_verdict(score):
    if score >= BOT_THRESHOLD:
        return "bot"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def score_edge(fp):
    """No JA4 header means the request didn't come through the edge."""
    if fp.present:
        return 0, []
    return 100, ["No X-JA4-Fingerprint: request bypassed the TLS edge"]


def evaluate(fp, headers, cookies, path, level):
    """
    Score one request.

    fp       EdgeFingerprint (edge_headers.from_headers)
    headers  case-insensitive request headers
    cookies  mapping of cookie name -> value
    path     request path (Layer 4 only protects some paths)

    Returns (score, reasons, verdict, engine). `engine` is the TLS browser
    family (or None), logged for the debrief report.
    """
    engine = tls_engine(fp, claimed_engine(headers.get("User-Agent", ""))) if fp.present else None
    layers = [
        (1, "L1", lambda: score_edge(fp)),
        (1, "L1", lambda: score_denylist(fp, headers) if fp.present else (0, [])),
        (2, "L2", lambda: score_tls_family(fp, headers) if fp.present else (0, [])),
        (3, "L3", lambda: score_h2(fp, engine)),
        (4, "L4", lambda: score_browser_proof(fp, engine, cookies, path)),
    ]
    score = 0
    reasons = []
    for min_level, tag, check in layers:
        if level < min_level:
            continue
        points, why = check()
        score += points
        reasons.extend(f"[{tag}] {r}" for r in why)
    return score, reasons, get_verdict(score), engine


if __name__ == "__main__":
    from edge_headers import EdgeFingerprint
    chrome_ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")
    samples = {
        "requests + Chrome UA": EdgeFingerprint("t13d1812h1_85036bcba153_b26ce05bbdd6", None, None),
        "curl_cffi chrome": EdgeFingerprint(
            "t13d1516h2_8daaf6152771_806a8c22fdea", None,
            "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p"),
    }
    for name, fp in samples.items():
        print(name)
        for level in range(5):
            score, reasons, verdict, _ = evaluate(fp, {"User-Agent": chrome_ua}, {}, "/api/products", level)
            print(f"  Level {level}: score={score:3} {verdict:10} {reasons}")
