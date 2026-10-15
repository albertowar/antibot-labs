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
    on_action(name, fn)                     fn(ctx, result) after a route action (checkout, login, ...)
"""

from collections import defaultdict

from flask import render_template
from markupsafe import Markup

SLOTS = defaultdict(list)
ENRICHERS = []
UNGATED = ["/static/", "/img/", "/lab/", "/whoami", "/health", "/favicon.ico"]
ACTION_HOOKS = defaultdict(list)
ROBOTS = []


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


def ungate(prefix):
    UNGATED.append(prefix)


def is_ungated(path):
    return any(path == p.rstrip("/") or path.startswith(p) for p in UNGATED)


def on_action(name, fn):
    ACTION_HOOKS[name].append(fn)


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
