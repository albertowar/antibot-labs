"""
Ctx: what a defense is allowed to see. Built once per request by demo_site/gate.py.

There is deliberately no `actor` field. X-Lab-Actor is ground truth for the
scoreboard and never reaches a check (tools/smoke.py greps for it).
"""

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EdgeInfo:
    """What a CDN or reverse proxy would pass to the origin about the connection."""
    ip: str
    asn: int = 0
    org: str = ""
    country: str = ""
    pool: str = ""          # pool name is an edge-side join key, not its type
    ja4: str = ""           # measured by a TLS edge (W2 Ch5) or claimed over plain HTTP
    ja4_source: str = ""    # "measured" | "claimed" | ""
    h2: str = ""


@dataclass
class UserAgent:
    raw: str = ""
    family: str = ""        # chrome | firefox | safari | edge | library | bot | empty | other
    major: int = 0
    mobile: bool = False
    is_library: bool = False
    is_bot: bool = False

    _LIB = re.compile(r"python-requests|python-httpx|httpx/|curl/|Go-http-client|okhttp|aiohttp|libwww|Wget|Java/", re.I)
    _BOT = re.compile(r"bot|crawler|spider|slurp|fetch|scan|GPTBot|ClaudeBot|CCBot|Bytespider", re.I)

    @classmethod
    def parse(cls, raw):
        ua = cls(raw=raw or "")
        if not raw:
            ua.family = "empty"
            return ua
        if cls._LIB.search(raw):
            ua.family, ua.is_library = "library", True
        elif cls._BOT.search(raw):
            ua.family, ua.is_bot = "bot", True
        elif "Edg/" in raw:
            ua.family = "edge"
        elif "Firefox/" in raw:
            ua.family = "firefox"
        elif "Chrome/" in raw:
            ua.family = "chrome"
        elif "Safari/" in raw and "Version/" in raw:
            ua.family = "safari"
        else:
            ua.family = "other"
        m = re.search(r"(?:Chrome|Firefox|Version|Edg)/(\d+)", raw)
        ua.major = int(m.group(1)) if m else 0
        ua.mobile = "Mobile" in raw or "Android" in raw or "iPhone" in raw
        return ua


class Session:
    """A Redis-backed session. `sid` is the opaque cookie; flags and counters live in a hash."""

    def __init__(self, redis, sid, new=False, ttl=7 * 24 * 3600):
        self.redis, self.sid, self.new, self.ttl = redis, sid, new, ttl
        self.key = f"lab:s:{sid}"

    def get(self, name, default=None):
        v = self.redis.hget(self.key, name)
        return default if v is None else v

    def set(self, name, value):
        self.redis.hset(self.key, name, value)
        self.redis.expire(self.key, self.ttl)

    def delete(self, name):
        self.redis.hdel(self.key, name)

    def incr(self, name, by=1):
        v = self.redis.hincrby(self.key, name, by)
        self.redis.expire(self.key, self.ttl)
        return v

    def all(self):
        return self.redis.hgetall(self.key)

    def ns(self, name):
        """A per-session key prefix for a defense's own state: `lab:s:<sid>:<name>:`."""
        return f"{self.key}:{name}:"

    def clear(self):
        for k in self.redis.scan_iter(f"{self.key}*"):
            self.redis.delete(k)

    @property
    def user_id(self):
        v = self.get("uid")
        return int(v) if v else None

    @property
    def age_seconds(self):
        import time
        created = self.get("created_at")
        return time.time() - float(created) if created else 0.0


@dataclass
class Ctx:
    method: str
    path: str
    host: str
    args: dict
    form: dict
    json: object
    cookies: dict
    headers: list               # [(name, value)] in arrival order, lab headers already stripped
    ua: UserAgent
    edge: EdgeInfo
    session: Session
    user: object                # models.User or None
    redis: object
    phase: str = "request"
    level: int = 0
    attrs: dict = field(default_factory=dict)   # enrichers write here; checks read
    notes: dict = field(default_factory=dict)   # goes to the decision log's `extra`
    _telemetry: object = None

    def header(self, name, default=None):
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return default

    @property
    def header_names(self):
        return [k for k, _ in self.headers]

    @property
    def ip(self):
        return self.edge.ip

    def telemetry(self, kind):
        """The latest payload this session posted to /api/telemetry with that `kind`, or None."""
        if self._telemetry is None:
            return None
        return self._telemetry(kind)

    def bucket(self, name, key):
        """Take one token from a named bucket (policy.RATE_LIMITS). True if allowed."""
        from . import store
        return store.token_bucket(self.redis, name, key)

    def note(self, **extra):
        self.notes.update(extra)
