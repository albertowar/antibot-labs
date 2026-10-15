"""The crawler gate: who is this client, and what lane is it entitled to? Ships done.

One Check, wired at LADDER[0], runs on every gated request and decides two things:

    1. Who is the client?   a claim (User-Agent token) and whatever the level can PROVE about it
    2. Which budget?        the verified lane (600 requests/min per identity) or the anonymous
                            lane (30 requests/min per egress IP), both token buckets in policy.py

Why one orchestrator instead of one Check per level (W4 Ch1 style)? The budget must be applied
AFTER every proof has had its say, at every level, and the ladder runs level-0 checks first.
So the levels live inside the gate, exactly as the chapter's rounds are defined:

    L0  believe the User-Agent                                   (the hole)
    L1  + reverse DNS: the PTR must end in the operator's suffix (defenses/rdns.py)
    L2  + forward-confirm the PTR, cache the verdict             (defenses/rdns.py)
    L3  + operator-published IP ranges, and *entitlement* scoping (defenses/ip_ranges.py)
    L4  + Web Bot Auth: verify the request signature              (defenses/web_bot_auth.py)
    L5  + trust policy, freshness window, nonce replay cache      (defenses/web_bot_auth.py)

Order matters. A signature (L4+) is checked first because it is the strongest claim and is
independent of the User-Agent and the IP. Then the UA claim is verified by whatever the claimed
operator supports: reverse DNS where documented, published ranges where not. A claim that cannot
be verified is *not* an error: it is an anonymous client that said something we could not check,
so it keeps the anonymous budget (a 429, never a 403) and the lab can show false negatives and
false positives side by side. Only a forged, tampered or replayed signature is refused outright
(403), because that client has proven it is lying rather than merely unverifiable.

Scope: the gate applies to clients that are not a mainstream browser (a library, a bot token, no
User-Agent at all, or any request carrying signature headers) and to anyone claiming to be an
operator. Browsers are out of scope here: shoppers behind carrier NAT share two addresses and a
30-a-minute budget would hurt them for nothing. The price is the one W4 Ch1 measured: a scraper
that dresses as Chrome never meets this gate.

Every decision is explained in the decision log (`extra.claim/identity/method/lane/reasons`);
the reasons are for teaching, in production you never tell a client which check it failed.
Verification is a cost: every DNS or directory round trip is paid in request latency, and it
shows up in the gate figure (`Server-Timing: gate`).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import ip_ranges, rdns, resolver, ua_claims, web_bot_auth
from .operators import OPERATORS
from .pipeline import Check, Signal, Verdict

BROWSERS = ("chrome", "firefox", "safari", "edge")


@dataclass
class Identity:
    claim: str | None = None       # what the User-Agent says
    identity: str | None = None    # what we could verify (operator key or agent origin)
    method: str | None = None      # ua | rdns | fcrdns | ip-range | web-bot-auth
    category: str | None = None
    lane: str = "anonymous"        # anonymous | verified
    block: bool = False            # True only for forged / replayed signatures
    reasons: list[str] = field(default_factory=list)


def in_scope(ctx) -> bool:
    return bool(ctx.header("Signature-Input") or ctx.header("Signature-Agent")
                or ua_claims.claim(ctx.ua.raw) or ctx.ua.family not in BROWSERS)


def identify(ctx) -> Identity:
    d = Identity(claim=ua_claims.claim(ctx.ua.raw))
    level, r = ctx.level, ctx.redis

    # --- Rounds 4-5: a signed request identifies itself cryptographically.
    if level >= 4 and ctx.header("Signature-Input"):
        res = web_bot_auth.verify(ctx)
        d.reasons.extend(res.reasons)
        if res.status == "verified":
            if level >= 5:
                t = web_bot_auth.trust(res, ctx)
                d.reasons.extend(t.reasons)
                d.block = t.block
                d.lane = "verified" if t.entitled else "anonymous"
            else:
                d.lane = "verified"
                d.reasons.append("L4: any valid signature gets the crawler lane")
            d.identity, d.method, d.category = res.agent, "web-bot-auth", "signed-agent"
            return d
        if res.status == "invalid" and level >= 5:
            d.block = True
            return d
        # "unverified" (or invalid at L4): fall through to the User-Agent path.

    # --- Round 0: what does the client say it is?
    claim = d.claim
    if claim is None:
        d.reasons.append("no identity claimed")
        return d
    op = OPERATORS[claim]
    if level == 0:
        d.identity, d.method, d.category, d.lane = claim, "ua", op["category"], "verified"
        d.reasons.append("L0: believed the User-Agent")
        return d

    # --- Rounds 1-2: reverse DNS for operators that document it.
    verified = False
    if op["rdns_suffixes"]:
        ok, reasons = rdns.verify(ctx.ip, op["rdns_suffixes"], level, resolver.get_resolver(), r)
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
        return d

    d.identity, d.category = claim, op["category"]
    if level >= 3:
        d.lane, why = ip_ranges.lane_for(claim, d.method, op)
        d.reasons.append(why)
    else:
        d.lane = "verified"
    return d


def _check(ctx):
    if not in_scope(ctx):
        return None
    d = identify(ctx)
    ctx.attrs["lane"] = d.lane
    ctx.note(claim=d.claim, identity=d.identity, method=d.method, category=d.category, lane=d.lane,
             reasons=d.reasons[-5:])
    if d.block:
        return Verdict("block", signals=(Signal("crawler_gate", "bad_signature", 100, "; ".join(d.reasons)[:200]),))
    bucket, key = ("crawl_verified", d.identity) if d.lane == "verified" else ("crawl_anonymous", ctx.ip)
    if not ctx.bucket(bucket, key):
        return Verdict("rate_limit", retry_after=5,
                       signals=(Signal("rate_limit", f"{d.lane}_budget", 0, "; ".join(d.reasons)[:200]),))
    return [Signal("crawler_gate", f"lane_{d.lane}", 0, d.method or "")]


CHECK = Check("crawler_gate", _check)
