"""
Chapter 5, Round 1 REFERENCE SOLUTION: server-side verification of a provider token.

(`python tools/checkpoint.py --round 1 --catch-up` installs it.)

The widget in the browser only *collects* a token. Your server must redeem it with the
provider's siteverify API and then decide. Most real-world "CAPTCHA bypasses" are mistakes
in this function, not broken puzzles. defenses/turnstile_check.py calls it for sign-ups
(`register`, fail closed) and the newsletter (`newsletter`, fail open).

The checklist this version implements:
  - a missing token is a failure
  - check `hostname`: a token solved on someone else's page is not yours
  - check `action`: a token minted for the newsletter must not unlock sign-up
  - check freshness (`challenge_ts`); the provider enforces single use
  - set a timeout, and choose the fail mode on purpose (fail_mode)

Trade-off: fail-closed on registration means a provider outage stops your sign-ups.
Fail-open means an outage is an open door. Pick per endpoint (policy.TURNSTILE_FAIL_MODE),
log every outage, and alert on it.

Works with the MOCK provider (provider/mock_turnstile.py, test keys, no network), and with
the real Cloudflare Turnstile API if you set SITEVERIFY_URL and CAPTCHA_SECRET (Bonus 2).

Try it on its own, with the store (or `python provider/mock_turnstile.py`) running:

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
    if not token:
        return Result(False, "missing token")
    if len(token) > 2048:   # Turnstile's documented maximum
        return Result(False, "token too long")

    try:
        r = _http.post(siteverify_url(), timeout=TIMEOUT_S,
                       data={"secret": policy.SECRET, "response": token, "remoteip": remoteip})
        r.raise_for_status()
        outcome = r.json()
    except Exception as exc:
        # Log every one of these and alert on the rate: an outage is either
        # a provider problem or somebody probing your fail mode.
        return Result(fail_mode == "open", f"provider error ({type(exc).__name__}): failing {fail_mode}")

    if not outcome.get("success"):
        return Result(False, f"provider rejected token: {outcome.get('error-codes')}", outcome)
    if outcome.get("hostname") not in expected_hostnames:
        return Result(False, f"token solved on {outcome.get('hostname')!r}, not on this site", outcome)
    if outcome.get("action") != expected_action:
        return Result(False, f"token minted for action {outcome.get('action')!r}, expected {expected_action!r}", outcome)
    try:
        if _age_seconds(outcome["challenge_ts"]) > MAX_TOKEN_AGE_S:
            return Result(False, "token is stale", outcome)
    except (KeyError, ValueError):
        return Result(False, "token has no usable challenge_ts", outcome)
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
