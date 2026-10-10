"""
Chapter 6 — Server-side verification of a provider token (Section 6.2, Round 1)

The widget in the browser only *collects* a token. Your server must redeem
it with the provider's siteverify API and then decide. Most real-world
"CAPTCHA bypasses" are mistakes in this function, not broken puzzles.

REFERENCE SOLUTION for Round 1 (tools/checkpoint.py 1 --catch-up installs it).
The checklist it implements:
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


def _age_seconds(challenge_ts):
    issued = datetime.fromisoformat(challenge_ts.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - issued).total_seconds()


def verify_token(token, *, remoteip, expected_action, expected_hostnames,
                 fail_mode="closed"):
    """Redeem `token` with the provider and decide whether to accept it."""
    if not token:
        return Verdict(False, "missing token")
    if len(token) > 2048:   # Turnstile's documented maximum
        return Verdict(False, "token too long")

    try:
        r = _http.post(SITEVERIFY_URL, timeout=TIMEOUT_S,
                       data={"secret": SECRET, "response": token, "remoteip": remoteip})
        r.raise_for_status()
        outcome = r.json()
    except Exception as exc:
        # Log every one of these and alert on the rate: an outage is either
        # a provider problem or somebody probing your fail mode.
        reason = f"provider error ({type(exc).__name__}): failing {fail_mode}"
        return Verdict(fail_mode == "open", reason)

    if not outcome.get("success"):
        return Verdict(False, f"provider rejected token: {outcome.get('error-codes')}", outcome)
    if outcome.get("hostname") not in expected_hostnames:
        return Verdict(False, f"token solved on {outcome.get('hostname')!r}, not on this site", outcome)
    if outcome.get("action") != expected_action:
        return Verdict(False, f"token minted for action {outcome.get('action')!r}, "
                              f"expected {expected_action!r}", outcome)
    try:
        if _age_seconds(outcome["challenge_ts"]) > MAX_TOKEN_AGE_S:
            return Verdict(False, "token is stale", outcome)
    except (KeyError, ValueError):
        return Verdict(False, "token has no usable challenge_ts", outcome)
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
