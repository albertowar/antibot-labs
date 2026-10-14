"""
ivt_scoring (Round 5): invalid-traffic scoring for the ad click tracker, GIVT first, then SIVT.

The economics. Click fraud profits from billable events nobody engaged with: drain an advertiser's
budget or inflate a publisher's payout. The Media Rating Council splits invalid traffic in two, and
so should you:

  GIVT, general invalid traffic: identifiable by routine means. Hard filters on what the request
        is: datacenter or proxy egress, a library or bot User-Agent, no Referer.
  SIVT, sophisticated invalid traffic: dressed as a residential browser with a Referer. The tell is
        the engagement funnel, which is expensive to fake well: a click with no impression, an
        impression-to-click gap no reader produces, a click rate no reader reaches.

The facts you get. demo_site/ext/economies.py serves POST /api/ads/impression and POST /api/ads/click
and fills ctx.attrs["ad"] = {"campaign", "had_impression", "dwell_ms"} before the check runs at
`action:ad_click`. The rest you read yourself: ctx.ua (parsed User-Agent), ctx.header("Referer"),
and netinfo.lookup(ctx.ip)["asn_type"] (datacenter | vpn | relay | residential | ...).

Signals (bands: 40 challenge, 75 block); name them `givt_*` and `sivt_*` so the scoreboard can split
the tiers:

    givt_datacenter 80   givt_bad_ua 80   givt_no_referrer 30   vpn_egress 25
    sivt_no_impression 80   sivt_dwell 80 (under MIN_DWELL_MS)   sivt_velocity 40 (over CLICK_CAP per minute)

Who it hurts. Privacy settings strip the Referer (30 points alone: observed, not discarded), VPN
users share datacenter-like ranges (25), a fast reader clicks quickly. Keep every floor well below
human behaviour and treat a borderline click as "observe", which is how the MRC frames filtration
versus reporting. Count clicks per session with ctx.redis.incr(...) and a 60-second expiry.

Reference: solutions/round5/defenses/ivt_scoring.py (or `checkpoint.py --round 5 --catch-up`)
"""

from . import netinfo
from .pipeline import Check, Signal

MIN_DWELL_MS = 300        # impression -> click faster than this is not a reader
CLICK_CAP = 8             # clicks per session per minute


def _check(ctx):
    ad = ctx.attrs.get("ad")
    if not ad:
        return None
    # TODO (Round 5): return a list of Signals (they add up), or None. GIVT filters first, then SIVT.
    return None


CHECK = Check("ivt_scoring", _check, phases=("action:ad_click",))
