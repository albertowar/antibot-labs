"""
Chapter 6 — Detecting the solver and serving on risk (Section 6.5, Round 4)

REFERENCE SOLUTION for Round 4 (tools/checkpoint.py --round 4 --catch-up installs it).

A puzzle that "anyone can solve for a price" is still a sensor. Around every
solve, the server knows things the solver can't easily fake:

  solve time          issue → submit. People need a few seconds to read and
                      type; a script needs milliseconds; a farm adds a 10–40 s
                      queue. (Simulated seconds: see labkit.TIME_SCALE.)
  issuer ≠ submitter  the IP or User-Agent that fetched the image differs from
                      the one that submitted the answer: rotating proxies,
                      split pipelines.
  failure velocity    wrong answers per IP in the last minute.

And before any puzzle: should this request see one at all? Serving every
visitor a CAPTCHA gives bots free practice and costs every human time.
should_challenge() uses Chapter 5 session signals instead.

False positives you will see, and should: a phone that hops from Wi-Fi to
cellular between fetch and submit (issuer ≠ submitter), slow readers in the
farm's 10–40 s band, deep links from email that skip the landing page.
That is why mismatch alone only steps up (a fresh challenge), and why the
slow band is a weak signal on its own.
"""

from dataclasses import dataclass, field

FAST_SOLVE_SIM_S = 2.0          # nobody reads and types 5–7 characters this fast
FARM_BAND_SIM_S = (10.0, 40.0)  # typical human-farm queue + solve time
FAIL_WINDOW_SIM_S = 60
FAIL_LIMIT = 3
BLOCK_AT, STEP_UP_AT = 60, 40


@dataclass
class Decision:
    action: str                 # "allow" | "step_up" | "block"
    score: int = 0
    reasons: list = field(default_factory=list)


def should_challenge(redis, session, ctx, now_sim):
    """Serve on risk: only show the CAPTCHA when Chapter 5 signals say so."""
    reasons = []
    if not session.get("landing"):
        reasons.append("no landing page in this session")
    if now_sim - session.get("created_sim", now_sim) < 3.0:
        reasons.append("session younger than 3 s")
    if int(redis.get(f"redeemed:ip:{ctx['ip']}") or 0) >= 2:
        reasons.append("this IP already redeemed twice")
    if session.get("captcha_failures", 0) > 0:
        reasons.append("earlier CAPTCHA failures in this session")
    return bool(reasons), reasons


def note_failure(redis, ctx, time_scale):
    key = f"fails:ip:{ctx['ip']}"
    n = redis.incr(key)
    if n == 1:
        redis.expire(key, max(1, int(FAIL_WINDOW_SIM_S / time_scale)))


def assess(redis, record, ctx, solve_sim_s):
    """Score one solve. `record` is what challenge_store.check() returned."""
    score, reasons = 0, []
    if solve_sim_s < FAST_SOLVE_SIM_S:
        score += 60
        reasons.append(f"solved in {solve_sim_s:.1f} s: faster than a person can read")
    if record.get("issuer_ip") != ctx["ip"]:
        score += 45
        reasons.append("image fetched from a different IP than the answer")
    if record.get("issuer_ua") != ctx["ua"]:
        score += 30
        reasons.append("image fetched by a different User-Agent")
    if int(redis.get(f"fails:ip:{ctx['ip']}") or 0) >= FAIL_LIMIT:
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
