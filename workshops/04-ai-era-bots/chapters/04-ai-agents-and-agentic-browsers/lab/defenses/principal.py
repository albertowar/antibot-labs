"""Who is acting? The one place the Round 1 and Round 3 answers are combined. (GIVEN glue.)

    human            nothing says "agent"
    declared_agent   it says it is one (a User-Agent token or a Signature-Agent claim): Round 1
    verified_agent   its Web Bot Auth signature verified against a trusted operator: Round 3

Every check that needs the principal calls `principal(ctx)`; the answer, and the identity behind it, are
computed once per request and cached in `ctx.attrs`. That matters for identity: the verifier spends
the signature's nonce, so a second verification of the same request would call a genuine one a replay.
Identity is only consulted from level 3 up; below that a signed agent is just a declared agent, which
is exactly what the earlier rounds should show.

The stages are looked up as module attributes at call time, so the hot reload picks up your edits.
"""

from . import agent_identity, agent_policy

NO_IDENTITY = {"status": "none", "operator": None, "keyid": None, "reasons": []}


def identity(ctx):
    """The verified-identity record for this request (Round 3); `none` below level 3."""
    ident = ctx.attrs.get("identity")
    if ident is None:
        ident = dict(NO_IDENTITY) if ctx.level < 3 else agent_identity.verify(ctx)
        ctx.attrs["identity"] = ident
    return ident


def principal(ctx):
    p = ctx.attrs.get("principal")
    if p is not None:
        return p
    p = agent_policy.classify(ctx)
    ident = identity(ctx)
    if ctx.level >= 3 and ident["status"] == "verified":
        p = {"kind": "verified_agent", "operator": ident["operator"],
             "evidence": list(p["evidence"]) + [f"Web Bot Auth signature by {ident['operator']}"]}
    ctx.attrs["principal"] = p
    ctx.note(principal=p["kind"], operator=p.get("operator"), identity=ident["status"])
    return p
