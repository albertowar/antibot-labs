"""
Correlation layer, inherited from W2 Ch8 (always on here)

Each sensor in sensors/ judges one request with one kind of evidence. This
layer asks questions that no single sensor can answer:

- telemetry_replay   Has this exact mouse/keyboard trace been seen in
                     another session? A human hand never produces the same
                     trace twice; a bot that captured one "good" sensor
                     blob and replays it does it every time.
- fp_reuse           Has this exact device fingerprint shown up from 4+
                     different IPs in 10 minutes? One laptop does not hop
                     across a residential proxy pool.
- tz_geo_mismatch    Does the browser's time zone sit on a different
                     continent from the IP's location?
- lang_mismatch      Does the Accept-Language header disagree with
                     navigator.languages? Real browsers derive both from the
                     same setting.

False positives:
- tz_geo_mismatch fires for every VPN user and every traveller. It scores
  10, enough to tip a borderline score, never enough to block. Tor exits are
  skipped: their location is meaningless and Tor Browser always reports UTC.
- fp_reuse can fire for fleets of identical managed devices (kiosks, school
  Chromebooks) behind different IPs. Real fingerprints carry enough
  entropy that this is rare, but check before raising the weight.
- telemetry_replay has no innocent explanation, which is why it is the
  heaviest signal in policy.py.

Cost: two Redis set operations per request, and the keys hold hashes, not
raw telemetry.
"""

LAYER = "correlation"
SIGNALS = {
    "telemetry_replay": "this exact behaviour trace was seen in another session",
    "fp_reuse": "this exact fingerprint came from 4+ IPs in 10 min",
    "tz_geo_mismatch": "browser time zone is on another continent from the IP",
    "lang_mismatch": "Accept-Language disagrees with navigator.languages",
}

FP_REUSE_IPS = 4


def _primary_language(header):
    return header.split(",")[0].split(";")[0].strip().lower()


def sense(ctx):
    t = ctx.telemetry
    if t is None:
        return []
    found = []
    if t["trace_hash"] and ctx.counters.add_distinct(ctx.sid, "trace", t["trace_hash"]) >= 2:
        found.append("telemetry_replay")
    if ctx.counters.add_distinct(ctx.edge["ip"], "fp-ips", t["fp_hash"]) >= FP_REUSE_IPS:
        found.append("fp_reuse")
    edge_tz = ctx.edge.get("tz")
    # A Tor exit's location says nothing about the user, and Tor Browser reports UTC
    if ctx.edge.get("type") != "tor" and edge_tz and t["timezone"] \
            and edge_tz.split("/")[0] != t["timezone"].split("/")[0]:
        found.append("tz_geo_mismatch")
    header = dict((k.lower(), v) for k, v in ctx.headers).get("accept-language", "")
    if header and t["languages"] and _primary_language(header) != t["languages"][0].lower():
        found.append("lang_mismatch")
    return found
