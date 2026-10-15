"""What the page's collector told us, and what the server saw for itself. (GIVEN infrastructure.)

Two sources, kept apart on purpose:

  * Client telemetry (`POST /api/telemetry {"kind": "agent", ...}`, sent by static/js/agent.js and,
    for the simulated shoppers, by tools/personas_ch4.py): a browser fingerprint and, per page, the
    pointer / key / scroll / overlay events the collector recorded. Evidence, never proof: it all
    runs in the client and can be forged (W2 Ch2).
  * The server's own flow log: when each HTML page was served to this session. A bot cannot edit it,
    so the cadence between pages is the one timing signal the client does not control.

The store's telemetry sink keeps only the latest payload per kind per session, so the handler in
demo_site/ext/agents.py accumulates one entry per page here. Everything lives in Redis under
`lab:s:<sid>:agent:` (the lab reset clears it).
"""

import json
import time

from . import fingerprint_coherence

TTL = 3600
MAX_FLOW = 50
DEVICE_PREFIX = "lab:agent:dev:"       # protected-drop units bought per device (counted by demo_site/ext/agents.py)


def _ns(ctx):
    return ctx.session.ns("agent")


def now_ms():
    return int(time.time() * 1000)


def record_telemetry(ctx, payload):
    """Store one page's telemetry. Returns what the collector gets back."""
    page = str(payload.get("page", ""))[:100]
    fp = payload.get("fp") if isinstance(payload.get("fp"), dict) else {}
    events = payload.get("events") if isinstance(payload.get("events"), dict) else {}
    ns, fph = _ns(ctx), fingerprint_coherence.fingerprint_hash(fp)
    pipe = ctx.redis.pipeline()
    pipe.set(ns + "fp", json.dumps(fp), ex=TTL)
    pipe.set(ns + "fph", fph, ex=TTL)
    pipe.set(ns + f"ev:{page}", json.dumps(events), ex=TTL)
    pipe.sadd(ns + "pages", page)
    pipe.expire(ns + "pages", TTL)
    pipe.execute()
    return {"fp_hash": fph, "page": page}


def record_flow(ctx):
    """Append this page view to the session's flow log (the server's clock, not the client's)."""
    key = _ns(ctx) + "flow"
    ctx.redis.rpush(key, json.dumps([now_ms(), ctx.path]))
    ctx.redis.ltrim(key, -MAX_FLOW, -1)
    ctx.redis.expire(key, TTL)


def state(ctx, page=None):
    """The session as the Round 2 and Round 4 defenses (and the W2 shadow stack) read it."""
    ns, r = _ns(ctx), ctx.redis
    page = page or f"/drop/{ctx.notes.get('sku', '')}"
    pages = {}
    for name in r.smembers(ns + "pages"):
        raw = r.get(ns + f"ev:{name}")
        if raw:
            pages[name] = json.loads(raw)
    fp = r.get(ns + "fp")
    return {
        "page": page, "pages": pages, "events": pages.get(page),
        "fp": json.loads(fp) if fp else None, "fp_hash": r.get(ns + "fph"),
        "flow": [json.loads(x) for x in r.lrange(ns + "flow", 0, -1)],
        "now_ms": now_ms(), "http_ua": ctx.ua.raw,
    }


def device_key(ctx):
    """'This browser on this machine': its fingerprint hash, however many fresh cookie jars it opens.

    A client that sent no telemetry (no JavaScript) falls back to its device cookie, then to its
    address. The fingerprint is what a fleet of contexts on one machine cannot rotate for free.
    """
    return ctx.redis.get(_ns(ctx) + "fph") or ctx.cookies.get("did") or ctx.ip
