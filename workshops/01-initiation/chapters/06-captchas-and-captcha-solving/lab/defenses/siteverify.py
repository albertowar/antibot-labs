"""
Chapter 6 — Server-side verification of a provider token (Section 6.2, Round 1)

The widget in the browser only *collects* a token. Your server must redeem
it with the provider's siteverify API and then decide. Most real-world
"CAPTCHA bypasses" are mistakes in this function, not broken puzzles.

As shipped, this is the verifier most people write: it checks `success`
and nothing else, it lets requests without a token through ("the widget
probably failed to load"), and it fails open when the provider errors.
attacks/round1_bypass.py gets past it four different ways.

Your job in Round 1: fix every TODO (Round 1). The checklist:
  - a missing token is a failure
  - check `hostname`: a token solved on someone else's page is not yours
  - check `action`: a token minted for the newsletter must not unlock signup
  - check freshness (`challenge_ts`); the provider enforces single use
  - set a timeout, and choose the fail mode on purpose (fail_mode)

Trade-off: fail-closed on registration means a provider outage stops your
signups. Fail-open means an outage is an open door. Pick per endpoint, log
every outage, and alert on it.

Works with the mock provider (provider/mock_turnstile.py), and with the real
Cloudflare Turnstile API if you set SITEVERIFY_URL and CAPTCHA_SECRET.
"""

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import PROVIDER_URL, SECRET  # noqa: E402

SITEVERIFY_URL = os.environ.get("SITEVERIFY_URL",
                                f"{PROVIDER_URL}/turnstile/v0/siteverify")
MAX_TOKEN_AGE_S = 300      # Turnstile tokens are valid for 300 s
TIMEOUT_S = 3.0

# One pooled client: keep-alive to the provider saves a TCP (and in
# production a TLS) handshake on every sign-up.
_http = httpx.Client()


@dataclass
class Verdict:
    ok: bool
    reason: str
    outcome: dict = field(default_factory=dict)


def verify_token(token, *, remoteip, expected_action, expected_hostnames,
                 fail_mode="closed"):
    """Redeem `token` with the provider and decide whether to accept it."""
    # TODO (Round 1): a missing token must be a failure, not a pass.
    if not token:
        return Verdict(True, "no token: widget probably failed to load, letting it through")

    try:
        # TODO (Round 1): pass timeout=TIMEOUT_S, and check the HTTP status.
        r = _http.post(SITEVERIFY_URL, data={"secret": SECRET, "response": token,
                                             "remoteip": remoteip})
        outcome = r.json()
    except Exception as exc:
        # TODO (Round 1): honour fail_mode ("closed" rejects, "open" accepts)
        #   instead of always accepting. Failing open here lets anyone in
        #   during an outage.
        return Verdict(True, f"provider error ({type(exc).__name__}): failing open")

    if not outcome.get("success"):
        return Verdict(False, f"provider rejected token: {outcome.get('error-codes')}", outcome)

    # TODO (Round 1): reject if outcome["hostname"] is not in expected_hostnames.
    # TODO (Round 1): reject if outcome["action"] != expected_action.
    # TODO (Round 1): reject if outcome["challenge_ts"] is older than MAX_TOKEN_AGE_S
    #   It looks like "2026-10-10T09:15:02.123Z"; on Python 3.10, replace the
    #   trailing "Z" with "+00:00" before datetime.fromisoformat().
    return Verdict(True, "provider accepted token", outcome)


if __name__ == "__main__":
    print("Exercise the verifier against the running mock provider:\n")
    from labkit import mint_token
    cases = {
        "valid register token": mint_token("198.51.100.7", "register"),
        "newsletter token": mint_token("203.0.113.9", "newsletter"),
        "token from another site": mint_token("203.0.113.9", "register",
                                              hostname="free-movies.example"),
        "no token": "",
    }
    for label, token in cases.items():
        v = verify_token(token, remoteip="198.51.100.7", expected_action="register",
                         expected_hostnames={"localhost", "127.0.0.1"})
        print(f"  {'accept' if v.ok else 'reject':<7} {label:<26} {v.reason}")
