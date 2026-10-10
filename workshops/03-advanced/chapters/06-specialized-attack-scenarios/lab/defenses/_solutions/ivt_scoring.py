"""Round 5 defense (REFERENCE SOLUTION) — invalid-traffic (IVT) scoring.

Economic chokepoint: the advertiser budget / publisher payout. The MRC splits
invalid traffic into two tiers, and so do we:

  GIVT (General Invalid Traffic) — identifiable by routine means. Cheap hard
  filters catch the unsophisticated flood:
     * datacenter egress          * missing referrer
     * missing / too-short UA      * self-declared bot UA

  SIVT (Sophisticated Invalid Traffic) — looks human on each request; the tell is
  in the engagement funnel, which the fraudster fakes badly because faking it well
  costs real time:
     * a click with no matching impression in the session
     * ~zero dwell between impression and click
     * click volume per session far above a human

False positive, named honestly: privacy users strip the Referer header, and a fast
reader can click quickly. The GIVT referrer rule and the SIVT dwell floor will
catch some real clicks; keep the floors well below human behaviour and treat
borderline traffic as "observe", not "discard", which is exactly how the MRC frames
filtration vs. reporting.
"""

from __future__ import annotations

from store import allow, block, Decision

MIN_DWELL_MS = 400
CLICK_CAP = 8   # clicks per session per window


def evaluate(ctx) -> Decision:
    # GIVT: routine, hard filters.
    if ctx["net_type"] == "datacenter":
        return block("givt:datacenter egress", score=100.0)
    ua = ctx["user_agent"] or ""
    if len(ua) < 20 or "bot" in ua.lower():
        return block("givt:bad user-agent", score=100.0)
    if not ctx["referrer"]:
        return block("givt:no referrer", score=80.0)
    # SIVT: engagement-funnel coherence.
    if not ctx["had_impression"]:
        return block("sivt:click without impression", score=90.0)
    if ctx["dwell_ms"] < MIN_DWELL_MS:
        return block(f"sivt:dwell {ctx['dwell_ms']:.0f}ms < {MIN_DWELL_MS}ms", score=85.0)
    if ctx["clicks_in_session"] > CLICK_CAP:
        return block(f"sivt:{ctx['clicks_in_session']} clicks/session", score=85.0)
    return allow("valid click")
