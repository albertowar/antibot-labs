"""
W2 Ch1 — The Edge Layer: Workshop 1 Header Rules, Always On

Everything Workshop 1, Chapter 4 built (User-Agent parsing, header presence
and Fetch Metadata, Client Hints, header order, Accept-CH negotiation) runs on
every request at every DEFENSE_LEVEL in this lab. It is the baseline the
attacker has to get past before the JavaScript sensor matters at all.

That is the starting point of this chapter: a raw HTTP client and an
unmodified headless browser are already caught here (Round 0). The browser
attacks in this lab override their User-Agent and Client Hints over the
Chrome DevTools Protocol, which makes the HTTP layer look clean, so the new
defenses have to look inside the JavaScript environment instead.

Thresholds are Workshop 1's: score >= 40 blocks, score >= 20 is logged as
suspicious.
"""

from accept_ch import score_accept_ch
from client_hints import score_client_hints
from header_inspector import score_header_consistency
from header_order import score_header_order
from ua_inspector import score_user_agent

BOT_THRESHOLD = 40
SUSPICIOUS_THRESHOLD = 20


def edge_verdict(score):
    if score >= BOT_THRESHOLD:
        return "bot"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def evaluate_edge(headers, header_names, cookies, host, secure_context):
    """Run all Workshop 1 header layers. Returns (score, reasons, verdict)."""
    ua_string = headers.get("User-Agent", "")
    layers = [
        ("W1-UA", lambda: score_user_agent(headers)),
        ("W1-headers", lambda: score_header_consistency(headers, host)),
        ("W1-hints", lambda: score_client_hints(headers, secure_context)),
        ("W1-order", lambda: score_header_order(header_names, ua_string)),
        ("W1-accept-ch", lambda: score_accept_ch(headers, cookies, secure_context)),
    ]
    score = 0
    reasons = []
    for tag, check in layers:
        points, why = check()
        score += points
        reasons.extend(f"[{tag}] {r}" for r in why)
    return score, reasons, edge_verdict(score)


if __name__ == '__main__':
    headers = {"Host": "localhost:5000", "User-Agent": "python-httpx/0.28.1",
               "Accept": "*/*", "Accept-Encoding": "gzip, deflate"}
    print(evaluate_edge(headers, list(headers), {}, "localhost:5000", True))
