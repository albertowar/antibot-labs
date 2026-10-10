"""
Chapter 4 — Header Scoring Engine (Section 4.5)

Runs every defense layer enabled by DEFENSE_LEVEL and adds up the points.

    Level 0  no defense (log only)
    Level 1  + User-Agent parsing          (ua_inspector.py)
    Level 2  + presence & consistency      (header_inspector.py)
    Level 3  + Client Hints & header order (client_hints.py, header_order.py)
    Level 4  + Accept-CH negotiation       (accept_ch.py)

Thresholds:
    score >= 40  bot         (403)
    score >= 20  suspicious  (logged, allowed through)
    score <  20  clean
"""

from accept_ch import score_accept_ch
from client_hints import score_client_hints
from header_inspector import score_header_consistency
from header_order import score_header_order
from ua_inspector import score_user_agent

BOT_THRESHOLD = 40
SUSPICIOUS_THRESHOLD = 20


def get_header_verdict(score):
    if score >= BOT_THRESHOLD:
        return "bot"
    elif score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "clean"


def evaluate(headers, header_names, cookies, host, secure_context, level):
    """
    Score a request with every layer up to `level`.

    headers         case-insensitive mapping of header name -> value
    header_names    header names in the order they arrived on the wire
    cookies         mapping of cookie name -> value
    host            the server's host:port (for Sec-Fetch-Site/Referer checks)
    secure_context  True for HTTPS or localhost (browsers only send hints there)

    Returns (score, reasons, verdict). Each reason is tagged with its layer.
    """
    ua_string = headers.get("User-Agent", "")
    layers = [
        (1, "L1", lambda: score_user_agent(headers)),
        (2, "L2", lambda: score_header_consistency(headers, host)),
        (3, "L3", lambda: score_client_hints(headers, secure_context)),
        (3, "L3", lambda: score_header_order(header_names, ua_string)),
        (4, "L4", lambda: score_accept_ch(headers, cookies, secure_context)),
    ]
    score = 0
    reasons = []
    for min_level, tag, check in layers:
        if level < min_level:
            continue
        points, why = check()
        score += points
        reasons.extend(f"[{tag}] {r}" for r in why)
    return score, reasons, get_header_verdict(score)


if __name__ == '__main__':
    headers = {
        "Host": "localhost:5000",
        "User-Agent": "python-requests/2.32.5",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }
    for level in range(5):
        score, reasons, verdict = evaluate(headers, list(headers), {}, "localhost:5000", True, level)
        print(f"Level {level}: score={score} verdict={verdict}")
        for r in reasons:
            print(f"  - {r}")
