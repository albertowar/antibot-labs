"""
What one login attempt is, as far as the layers are concerned.

A challenged login is answered twice: the first POST is scored and challenged, the client solves
the challenge, and the same login is sent again. The layers must score and count that as ONE
attempt, or a CGNAT user who solved a proof-of-work would count twice against their address
and a failed login would count twice against its cluster. `resumed()` is how a layer knows,
and since contract 1.7 the gate computes it (`ctx.resumed`: a valid clearance existed for a
registered challenge type when the Ctx was built) instead of this module reading the gate's
private clearance keys.
"""

CHALLENGES = ("pow", "step_up")


def resumed(ctx):
    """True when this request is the retry that follows a solved challenge."""
    return ctx.resumed


def credentials(ctx):
    """(email, password) from a form or a JSON body, whichever the client used."""
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return str(body.get("email", "")).strip().lower(), str(body.get("password", ""))


def field(ctx, name):
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return body.get(name)
