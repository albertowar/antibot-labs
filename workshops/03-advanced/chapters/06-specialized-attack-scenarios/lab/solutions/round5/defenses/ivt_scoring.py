"""
ivt_scoring (Round 5, reference): invalid-traffic scoring for the ad click tracker, GIVT first, then SIVT.

The economics. Click fraud profits from billable events nobody engaged with. The MRC splits invalid
traffic in two, and so do we:

  GIVT (general): identifiable by routine means. Hard filters on what the request is: datacenter or
       proxy egress, a library or bot User-Agent, no Referer.
  SIVT (sophisticated): dressed as a residential browser with a Referer. The tell is the engagement
       funnel, which is expensive to fake well: a click without an impression, an impression-to-click
       gap no reader produces, a click rate no reader reaches.

Signals add up on the starter's scale (75 blocks). A datacenter egress or a library User-Agent blocks
alone; a missing Referer (30) and a VPN egress (25) only get observed, and together still stay below the
challenge band. Tags `givt_*` / `sivt_*` let the scoreboard split the tiers.

Who it hurts. Privacy settings strip the Referer, VPN users share datacenter-like ranges, a fast reader
clicks quickly. The floors are well below human behaviour and the borderline signals sit below the
challenge band: observe, do not discard. What it misses: a click farm of real devices with real
engagement, and anything that waits long enough; this is an adversarial, moving target.
"""

from . import netinfo
from .pipeline import Check, Signal

MIN_DWELL_MS = 300
CLICK_CAP = 8


def _check(ctx):
    ad = ctx.attrs.get("ad")
    if not ad:
        return None
    signals = []
    kind = netinfo.lookup(ctx.ip)["asn_type"]
    if kind == "datacenter":
        signals.append(Signal("ivt", "givt_datacenter", 80, f"{ctx.edge.org or ctx.ip}"))
    elif kind == "vpn":
        signals.append(Signal("ivt", "vpn_egress", 25, ctx.edge.org))
    ua = ctx.ua
    if ua.is_library or ua.is_bot or len(ua.raw) < 20:
        signals.append(Signal("ivt", "givt_bad_ua", 80, ua.raw[:40]))
    if not ctx.header("Referer"):
        signals.append(Signal("ivt", "givt_no_referrer", 30))
    if not ad["had_impression"]:
        signals.append(Signal("ivt", "sivt_no_impression", 80, "click with no impression in this session"))
    elif ad["dwell_ms"] < MIN_DWELL_MS:
        signals.append(Signal("ivt", "sivt_dwell", 80, f"{ad['dwell_ms']:.0f} ms < {MIN_DWELL_MS} ms"))
    key = f"lab:ads:clicks:{ctx.session.sid}"
    clicks = ctx.redis.incr(key)
    ctx.redis.expire(key, 60)
    if clicks > CLICK_CAP:
        signals.append(Signal("ivt", "sivt_velocity", 40, f"{clicks} clicks this minute"))
    return signals or None


CHECK = Check("ivt_scoring", _check, phases=("action:ad_click",))
