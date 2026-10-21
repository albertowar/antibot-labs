"""
Small helpers shared by the Chapter 2 header checks (not a check itself).

`lowered(ctx)` is the request's headers as a lower-cased dict; `ctx.headers` (the ordered list) stays the
source of truth for anything about order. `demo_ctx(...)` builds a stand-in Ctx so each module's
`__main__` can run on its own: `python -m defenses.ua_inspector` from the lab folder.
"""

from types import SimpleNamespace

from .context import UserAgent

LOCALHOST_NAMES = ("localhost", "127.0.0.1", "[::1]", "::1")


def lowered(ctx):
    """Header name (lower case) -> value. A repeated header keeps the last value."""
    return {k.lower(): v for k, v in ctx.headers}


def secure_context(ctx):
    """Browsers only send Client Hints on HTTPS or http://localhost, so the checks only expect them there.

    The lab only runs on localhost. Behind a real TLS terminator, add `or scheme == "https"` (the scheme
    comes from the edge, e.g. X-Forwarded-Proto, and only if the edge is the one setting it).
    """
    return ctx.host.rsplit(":", 1)[0].lower() in LOCALHOST_NAMES or ctx.host.lower() in LOCALHOST_NAMES


def demo_ctx(headers, cookies=None, host="127.0.0.1:5000"):
    """A minimal Ctx for the `__main__` demos: headers as an ordered list or dict."""
    pairs = list(headers.items()) if isinstance(headers, dict) else list(headers)
    ua = next((v for k, v in pairs if k.lower() == "user-agent"), "")
    ctx = SimpleNamespace(headers=pairs, header_names=[k for k, _ in pairs], cookies=dict(cookies or {}), host=host, ua=UserAgent.parse(ua), notes={})
    ctx.header = lambda name, default=None: next((v for k, v in pairs if k.lower() == name.lower()), default)
    ctx.note = lambda **kw: ctx.notes.update(kw)
    return ctx


def note_reasons(ctx, signals):
    """Put a check's human-readable reasons in the decision log (`extra.header_reasons`, read by /lab/headers/logs)."""
    if signals:
        ctx.notes.setdefault("header_reasons", []).extend(f"{s.flag()}: {s.detail}" for s in signals if s.points)


def show(label, signals):
    print(f"\n{label}: score={sum(s.points for s in signals)}")
    for s in signals:
        print(f"  - {s.flag()} ({s.points}): {s.detail}")
