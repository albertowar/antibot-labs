"""
Round 3: Correlation layer (DEFENSE_LEVEL >= 3)

Each sensor judges one request with one kind of evidence. This layer asks questions that no
single sensor can answer:

- telemetry_replay   Has this exact mouse/keyboard trace been seen in another session? A human
                     hand never produces the same trace twice; a bot that captured one "good"
                     sensor blob and replays it does it every time.
- fp_reuse           Has this exact device fingerprint shown up from 4+ different IPs in 10
                     minutes? One laptop does not hop across a residential proxy pool.
- tz_geo_mismatch    Does the browser's time zone sit on a different continent from the IP's
                     location?
- lang_mismatch      Does the Accept-Language header disagree with navigator.languages? Real
                     browsers derive both from the same setting.

False positives:
- tz_geo_mismatch fires for every VPN user and every traveller. It scores 10, enough to tip a
  borderline score, never enough to block. Tor exits are skipped: their location is meaningless
  and Tor Browser always reports UTC.
- fp_reuse can fire for fleets of identical managed devices (kiosks, school Chromebooks) behind
  different IPs. Real fingerprints carry enough entropy that this is rare, but check before
  raising the weight.
- telemetry_replay has no innocent explanation, which is why it is the heaviest signal in
  policy.py.

Cost: two Redis set operations per request, and the keys hold hashes, not raw telemetry.
"""

from . import features, sensors
from . import netinfo_ch8 as netinfo
from .pipeline import Check

LAYER = "correlation"
SIGNALS = {
    "telemetry_replay": "this exact behaviour trace was seen in another session",
    "fp_reuse": "this exact fingerprint came from 4+ IPs in 10 min",
    "tz_geo_mismatch": "browser time zone is on another continent from the IP",
    "lang_mismatch": "Accept-Language disagrees with navigator.languages",
}

FP_REUSE_IPS = 4
WINDOW = 600


def _distinct(redis, key, member):
    """Add `member` to a windowed set and return how many distinct members it has."""
    redis.sadd(key, member)
    redis.expire(key, WINDOW)
    return redis.scard(key)


def _primary_language(header):
    return header.split(",")[0].split(";")[0].strip().lower()


def sense(ctx):
    t = features.of(ctx)
    if t is None:
        return []
    found = []
    if t["trace_hash"] and _distinct(ctx.redis, f"lab:ch8:trace:{t['trace_hash']}", ctx.session.sid) >= 2:
        found.append("telemetry_replay")
    if _distinct(ctx.redis, f"lab:ch8:fp-ips:{t['fp_hash']}", ctx.edge.ip) >= FP_REUSE_IPS:
        found.append("fp_reuse")
    continent = netinfo.CONTINENT.get(ctx.edge.country)
    # A Tor exit's location says nothing about the user, and Tor Browser reports UTC
    if netinfo.of(ctx)["kind"] != "tor" and continent and t["timezone"] \
            and continent != t["timezone"].split("/")[0]:
        found.append("tz_geo_mismatch")
    header = ctx.header("accept-language") or ""
    if header and t["languages"] and _primary_language(header) != t["languages"][0].lower():
        found.append("lang_mismatch")
    return found


CHECK = Check("correlation", lambda ctx: sensors.emit(ctx, LAYER, sense(ctx)), phases=sensors.LOGIN)
