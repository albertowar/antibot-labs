"""
Chapter 5, Round 4 (L4) REFERENCE SOLUTION: detecting the solver and serving the CAPTCHA on risk.

(`python tools/checkpoint.py --round 4 --catch-up` installs it.)

A puzzle that "anyone can solve for a price" is still a sensor. Around every solve, the
server knows things the solver can't easily fake:

  solve time          issue -> submit. People need a few seconds to read and type; a script
                      needs milliseconds; a farm adds a 10-40 s queue. (Simulated seconds:
                      policy.TIME_SCALE.)
  issuer != submitter the IP or User-Agent that fetched the image differs from the one that
                      submitted the answer: rotating proxies, split pipelines.
  failure velocity    wrong answers per IP in the last minute.

And before any puzzle: should this request see one at all? Serving every visitor a CAPTCHA
gives bots free practice and costs every human time. should_challenge() uses session signals
instead (CHECK, below, is what runs at L4; defenses/captcha_gate.py steps aside at L4).

False positives you will see, and should: a phone that hops from Wi-Fi to cellular between
fetch and submit (issuer != submitter), slow readers in the farm's 10-40 s band, deep links from
email that skip the landing page, phones behind one carrier-NAT address that all "redeemed
already". That is why mismatch alone only steps up (a fresh challenge), and why the slow band is
a weak signal on its own.

`ctx` is the request's Ctx. The landing-page flag is written by demo_site/ext/captcha.py (an
enricher that sets session flag `landing` on GET /).
"""

from dataclasses import dataclass, field

from . import policy
from .pipeline import Check, Signal, Verdict

FAST_SOLVE_SIM_S = 2.0          # nobody reads and types 5-7 characters this fast
FARM_BAND_SIM_S = (10.0, 40.0)  # typical human-farm queue + solve time
FAIL_WINDOW_SIM_S = 60
FAIL_LIMIT = 3
BLOCK_AT, STEP_UP_AT = 60, 40
RISK_POINTS = 45                # a risky session earns a CAPTCHA (>= policy.BANDS["challenge"])


@dataclass
class Decision:
    action: str                 # "allow" | "step_up" | "block"
    score: int = 0
    reasons: list = field(default_factory=list)


def _fails_key(ctx):
    return f"lab:captcha:fails:ip:{ctx.ip}"


def redeemed_key(ctx):
    return policy.redeemed_key(ctx.ip)


def should_challenge(ctx):
    """Serve on risk: only show the CAPTCHA when session signals say so."""
    reasons = []
    if not ctx.session.get("landing"):
        reasons.append("no landing page in this session")
    if ctx.session.age_seconds * policy.TIME_SCALE < 3.0:
        reasons.append("session younger than 3 s")
    if int(ctx.redis.get(redeemed_key(ctx)) or 0) >= 2:
        reasons.append("this IP already redeemed twice")
    if int(ctx.session.get("captcha_failures", 0)) > 0:
        reasons.append("earlier CAPTCHA failures in this session")
    return bool(reasons), reasons


def note_failure(ctx):
    """Called by captcha_gate.verify() on every wrong or rejected answer."""
    key = _fails_key(ctx)
    n = ctx.redis.incr(key)
    if n == 1:
        ctx.redis.expire(key, max(1, int(FAIL_WINDOW_SIM_S / policy.TIME_SCALE)))


def assess(ctx, record, solve_sim_s):
    """Score one correct solve. `record` is what challenge_store.check() returned."""
    score, reasons = 0, []
    if solve_sim_s < FAST_SOLVE_SIM_S:
        score += 60
        reasons.append(f"solved in {solve_sim_s:.1f} s: faster than a person can read")
    if record.get("issuer_ip") != ctx.ip:
        score += 45
        reasons.append("image fetched from a different IP than the answer")
    if record.get("issuer_ua") != ctx.ua.raw:
        score += 30
        reasons.append("image fetched by a different User-Agent")
    if int(ctx.redis.get(_fails_key(ctx)) or 0) >= FAIL_LIMIT:
        score += 40
        reasons.append(f"{FAIL_LIMIT}+ wrong answers from this IP in the last minute")
    lo, hi = FARM_BAND_SIM_S
    if lo <= solve_sim_s <= hi:
        score += 15
        reasons.append(f"solve time {solve_sim_s:.0f} s is in the farm band")

    if score >= BLOCK_AT:
        return Decision("block", score, reasons)
    if score >= STEP_UP_AT:
        return Decision("step_up", score, reasons)
    return Decision("allow", score, reasons)


def _check(ctx):
    required, reasons = should_challenge(ctx)
    ctx.note(captcha_risk=reasons)
    if not required:
        return None
    return Verdict("challenge", signals=(Signal("captcha", "risky_session", RISK_POINTS, "; ".join(reasons)[:60]),),
                   challenge="captcha")


CHECK = Check("solver_signals", _check, phases=("action:promo_redeem",))
