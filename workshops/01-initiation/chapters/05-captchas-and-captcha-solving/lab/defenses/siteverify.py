"""
Chapter 5, Round 1: server-side verification of a provider token (section 5.2).

The widget in the browser only *collects* a token. Your server must redeem it with the
provider's siteverify API and then decide. Most real-world "CAPTCHA bypasses" are mistakes
in this function, not broken puzzles. defenses/turnstile_check.py calls it for sign-ups
(`register`, fail closed) and the newsletter (`newsletter`, fail open).

As shipped, it trusts too much: attacks/round1_bypass.py gets in with no token, with a
newsletter token, with a token solved on another site, and during a provider outage.

Your job in Round 1: fix the five TODO (Round 1) so that
  - a missing token is a failure
  - the call has a timeout and checks the HTTP status
  - an outage follows fail_mode on purpose instead of always letting people in
  - `hostname` and `action` match: a token solved on someone else's page, or minted for the
    newsletter, must not unlock sign-up
  - the token is fresh (`challenge_ts`); the provider enforces single use

Trade-off: fail-closed on registration means a provider outage stops your sign-ups.
Fail-open means an outage is an open door. Pick per endpoint (policy.TURNSTILE_FAIL_MODE),
log every outage, and alert on it.

Works with the MOCK provider (provider/mock_turnstile.py, test keys, no network), and with
the real Cloudflare Turnstile API if you set SITEVERIFY_URL and CAPTCHA_SECRET (Bonus 2).

Try it on its own, with the store (or `python provider/mock_turnstile.py`) running; when the
TODOs are done it prints 1 accept and 3 rejects:

    python -m defenses.siteverify
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from . import policy

MAX_TOKEN_AGE_S = 300      # Turnstile tokens are valid for 300 s
TIMEOUT_S = 3.0

# One pooled client: keep-alive to the provider saves a TCP (and in
# production a TLS) handshake on every sign-up.
_http = httpx.Client()


def siteverify_url():
    base = os.environ.get("PROVIDER_URL", "http://127.0.0.1:5001")
    return os.environ.get("SITEVERIFY_URL", f"{base}/turnstile/v0/siteverify")


@dataclass
class Result:
    ok: bool
    reason: str
    outcome: dict = field(default_factory=dict)


def _age_seconds(challenge_ts):
    issued = datetime.fromisoformat(challenge_ts.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - issued).total_seconds()


def verify_token(token, *, remoteip, expected_action, expected_hostnames, fail_mode="closed"):
    """Redeem `token` with the provider and decide whether to accept it."""
    # TODO (Round 1): a missing token must be a failure, not a pass.
    if not token:
        return Result(True, "no token: widget probably failed to load, letting it through")

    try:
        # TODO (Round 1): pass timeout=TIMEOUT_S, and check the HTTP status (r.raise_for_status()).
        r = _http.post(siteverify_url(),
                       data={"secret": policy.SECRET, "response": token, "remoteip": remoteip})
        outcome = r.json()
    except Exception as exc:
        # TODO (Round 1): honour fail_mode ("closed" rejects, "open" accepts) instead of
        #   always accepting. Failing open here lets anyone in during an outage.
        return Result(True, f"provider error ({type(exc).__name__}): failing open")

    if not outcome.get("success"):
        return Result(False, f"provider rejected token: {outcome.get('error-codes')}", outcome)

    # TODO (Round 1): reject if outcome["hostname"] is not in expected_hostnames, and if
    #   outcome["action"] != expected_action.
    # TODO (Round 1): reject if outcome["challenge_ts"] is older than MAX_TOKEN_AGE_S
    #   (_age_seconds() parses it), or missing.
    return Result(True, "provider accepted token", outcome)

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    from captcha_kit import mint_token

    print("Exercise the verifier against the running mock provider:\n")
    cases = {
        "valid register token": mint_token("192.0.2.10", "register"),
        "newsletter token": mint_token("203.0.113.9", "newsletter"),
        "token from another site": mint_token("203.0.113.9", "register", hostname="free-movies.example"),
        "no token": "",
    }
    for label, token in cases.items():
        v = verify_token(token, remoteip="192.0.2.10", expected_action="register",
                         expected_hostnames=policy.OUR_HOSTNAMES)
        print(f"  {'accept' if v.ok else 'reject':<7} {label:<26} {v.reason}")
