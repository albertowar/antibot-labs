"""The crawler gate: who is this client, and what is it entitled to? Ships done.

One function, `decide()`, runs on every gated request and returns a Decision. The
rounds change what it trusts, by DEFENSE_LEVEL:

    L0  believe the User-Agent                                  (the hole)
    L1  + reverse DNS: the PTR must end in the operator's suffix (defenses/rdns.py)
    L2  + forward-confirm the PTR, cache the verdict             (defenses/rdns.py)
    L3  + operator-published IP ranges, and *entitlement* scoping (defenses/ip_ranges.py)
    L4  + Web Bot Auth: verify the request signature              (defenses/web_bot_auth.py)
    L5  + trust policy, freshness window, nonce replay cache      (defenses/web_bot_auth.py)

Order matters. A signature (L4+) is checked first because it is the strongest
claim and independent of UA and IP. Then the UA claim is verified by whatever the
claimed operator supports: reverse DNS where documented, published ranges where
not. A claim that cannot be verified is *not* an error, it is an anonymous client
that said something we could not check; it keeps the anonymous budget so the lab
can show false negatives and false positives side by side. Only a forged or
replayed signature is rejected outright (403), because that client has proven it
is lying rather than merely unverifiable.

Verification is a cost: every DNS or directory round trip is paid in request
latency. `cost_ms` is logged per decision so the scoreboard can show it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import ip_ranges
import rdns
import ua_claims
import web_bot_auth
from operators import OPERATORS


@dataclass
class RequestContext:
    ip: str
    method: str
    authority: str
    path: str
    query: str
    headers: dict[str, str]        # lower-cased names
    actor: str = "you"


@dataclass
class Decision:
    claim: str | None = None       # what the User-Agent says
    identity: str | None = None    # what we could verify (operator key or agent origin)
    method: str | None = None      # ua | rdns | fcrdns | ip-range | web-bot-auth
    category: str | None = None
    lane: str = "anonymous"        # anonymous | verified
    block: bool = False            # True only for forged / replayed signatures
    reasons: list[str] = field(default_factory=list)
    cost_ms: float = 0.0


def decide(ctx: RequestContext, level: int, r, resolver) -> Decision:
    t0 = time.perf_counter()
    d = Decision()
    try:
        _decide(ctx, level, r, resolver, d)
    finally:
        d.cost_ms = (time.perf_counter() - t0) * 1000
    return d


def _decide(ctx: RequestContext, level: int, r, resolver, d: Decision) -> None:
    d.claim = ua_claims.claim(ctx.headers.get("user-agent", ""))

    # --- Round 4/5: a signed request identifies itself cryptographically.
    if level >= 4 and "signature-input" in ctx.headers:
        res = web_bot_auth.verify(ctx, r, level)
        d.reasons.extend(res.reasons)
        if res.status == "verified":
            lane, reasons, block = web_bot_auth.policy(res, r, level)
            d.reasons.extend(reasons)
            d.identity, d.method, d.category = res.agent, "web-bot-auth", "signed-agent"
            d.lane, d.block = lane, block
            return
        if res.status == "invalid" and level >= 5:
            d.block = True
            return
        # "unverified" (or invalid at L4): fall through to the User-Agent path.

    # --- Round 0: what does the client say it is?
    claim = d.claim
    if claim is None:
        d.reasons.append("no identity claimed")
        return
    op = OPERATORS[claim]
    if level == 0:
        d.identity, d.method, d.category, d.lane = claim, "ua", op["category"], "verified"
        d.reasons.append("L0: believed the User-Agent")
        return

    # --- Rounds 1-2: reverse DNS for operators that document it.
    verified = False
    if op["rdns_suffixes"]:
        ok, reasons = rdns.verify(ctx.ip, op["rdns_suffixes"], level, resolver, r)
        d.reasons.extend(reasons)
        if ok:
            verified, d.method = True, ("fcrdns" if level >= 2 else "rdns")
    elif level < 3:
        d.reasons.append(f"{claim} publishes no reverse DNS; nothing to check at L{level}")

    # --- Round 3: published IP ranges for everyone else.
    if not verified and level >= 3 and op["ranges"]:
        hit = ip_ranges.lookup(ctx.ip, r)
        if hit and hit.operator == claim:
            verified, d.method = True, "ip-range"
            d.reasons.append(f"{ctx.ip} in {hit.list_path} ({hit.prefix})")
        elif hit:
            d.reasons.append(f"{ctx.ip} belongs to {hit.operator} ({hit.list_path}); claim was {claim}")
        else:
            d.reasons.append(f"{ctx.ip} is in no published range of {claim}")

    if not verified:
        d.reasons.append(f"claimed {claim}, could not verify: anonymous lane")
        return

    d.identity, d.category = claim, op["category"]
    if level >= 3:
        d.lane, why = ip_ranges.lane_for(claim, d.method, op)
        d.reasons.append(why)
    else:
        d.lane = "verified"
