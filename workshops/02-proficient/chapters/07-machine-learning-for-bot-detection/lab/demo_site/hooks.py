"""
Hook points for chapters. An ext module (demo_site/ext/<name>.py) calls these
from its init(app). Starter files are never edited by a lab.

    slot(name, template)                    render a chapter template inside base.html or a form:
                                            "head", "body_end", "nav", "form:checkout", "form:login",
                                            "form:register", "form:drop", "form:review", "product:aside"
    telemetry.register(kind, handler)       handle POST /api/telemetry {"kind": kind, ...}
    challenges.register(type, issue, verify, render=None)
                                            a challenge type the policy "challenge" band can serve
    enricher(fn)                            fn(ctx) runs before the checks; fill ctx.attrs
    ungate(prefix)                          paths the gate skips (static assets, your lab routes)
    ungate(prefix, session=True)            skip the ladder but still build the Ctx, set the session
                                            cookie, run enrichers and write a decision row (for a lab
                                            page that must run a collector or post telemetry)
    on_action(name, fn)                     fn(ctx, result, response) after a route's write or outcome
                                            (review/checkout/drop_buy after the row is written;
                                            register after the account; login after EVERY attempt,
                                            with result={"user":..., "ok": bool, "reason":...});
                                            return a replacement response to hold/swap it, or None
    on_response(fn)                         fn(info) on every response, gated or not, just before the
                                            gate stamps it; info: ctx (None if ungated), path, method,
                                            status, response, edge, gated. Time counts as gate cost.
    on_reset(fn)                            fn(app) after POST /lab/reset clears core state: drop or
                                            reseed the tables and Redis keys your ext owns
    stopped_outcome(*names)                 count chapter outcomes (g.outcome values like "paywalled")
                                            as stops in the scoreboard's stopped column and hurt rule
"""

from collections import defaultdict
from dataclasses import dataclass

from flask import render_template
from markupsafe import Markup

SLOTS = defaultdict(list)
ENRICHERS = []
UNGATED = [("/static/", "skip"), ("/img/", "skip"), ("/lab/", "skip"), ("/whoami", "skip"),
           ("/health", "skip"), ("/favicon.ico", "skip")]
ACTION_HOOKS = defaultdict(list)
RESPONSE_HOOKS = []
RESET_HOOKS = []
ROBOTS = []

# Outcomes the scoreboard counts as a stop (its `stopped` column and the hurt rule).
# stopped_outcome() lets a chapter add its own (g.outcome values such as "paywalled").
STOPPED_OUTCOMES = {"blocked", "challenged", "rate_limited", "deceived"}


def slot(name, template):
    SLOTS[name].append(template)


def robots(provider):
    """Extra robots.txt lines: `provider` is a callable returning an iterable of lines.

    Called on every GET /robots.txt, so a chapter can vary its lines with the current
    DEFENSE_LEVEL (bait Disallow entries, crawl policy). The base policy is unchanged
    when nothing registers.
    """
    ROBOTS.append(provider)


def render_slot(name, **ctx):
    parts = [render_template(t, **ctx) for t in SLOTS.get(name, [])]
    return Markup("\n".join(parts))


def enricher(fn):
    ENRICHERS.append(fn)
    return fn


def ungate(prefix, session=False):
    """Skip the gate's ladder for `prefix`. With session=True the gate still builds the Ctx
    (session cookie, enrichers, a decision row), it just never runs checks or blocks."""
    UNGATED.append((prefix, "session" if session else "skip"))


def ungate_mode(path):
    """None (gated), "skip" or "session" — the longest matching prefix wins."""
    best = None
    for p, mode in UNGATED:
        if (path == p.rstrip("/") or path.startswith(p)) and (best is None or len(p) > len(best[0])):
            best = (p, mode)
    return best[1] if best else None


def is_ungated(path):
    return ungate_mode(path) is not None


def on_action(name, fn):
    ACTION_HOOKS[name].append(fn)


@dataclass
class ResponseInfo:
    """What an on_response hook sees. `ctx` is None on an ungated path; `edge` is the raw
    lab-edge dict ({"ip": ..., "asn": ...}), present even when no Ctx was built."""
    ctx: object
    path: str
    method: str
    status: int
    response: object
    edge: dict
    gated: bool


def on_response(fn):
    """Register fn(info: ResponseInfo): runs on every response (gated and ungated) just before
    the gate stamps it, in registration order. Its time counts as gate cost when a Ctx exists;
    an exception is noted on the Ctx, never raised."""
    RESPONSE_HOOKS.append(fn)


def stopped_outcome(*names):
    STOPPED_OUTCOMES.update(names)


def on_reset(fn):
    """Register fn(app), run after POST /lab/reset clears the core store (reseed/clear ext tables)."""
    RESET_HOOKS.append(fn)


class Telemetry:
    def __init__(self):
        self.handlers = {}

    def register(self, kind, handler):
        """handler(ctx, payload) -> dict (returned to the client) or None."""
        self.handlers[kind] = handler

    def kinds(self):
        return sorted(self.handlers)


class Challenges:
    """Registry of challenge types. The gate serves one when the verdict is `challenge`."""

    def __init__(self):
        self.types = {}

    def register(self, name, issue, verify, render=None, api=True, clearance_ttl=None, uses=None):
        """
        issue(ctx) -> dict: the challenge payload (sent as JSON, and to `render`)
        verify(ctx, answer: dict) -> bool, or (bool, reason): the reason goes to the client's error
               message and to the decision log (`extra.challenge_reason`)
        render: a template for the HTML interstitial; None uses templates/challenge.html
        clearance_ttl: seconds a solved challenge clears the session (default policy.CLEARANCE_TTL)
        uses: how many challenge verdicts one solve absorbs (default unlimited within the TTL)

        Register the module's functions through a lambda (`issue=lambda ctx: mod.issue(ctx)`) if
        they live in defenses/: the reloader replaces modules, not the references you hold.
        """
        self.types[name] = {"issue": issue, "verify": verify, "render": render, "api": api,
                            "clearance_ttl": clearance_ttl, "uses": uses}

    def get(self, name):
        return self.types.get(name)

    def names(self):
        return sorted(self.types)


telemetry = Telemetry()
challenges = Challenges()
