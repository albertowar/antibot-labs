"""
Round 5 attack: click fraud against the ad tracker.

The economy: drain an advertiser's budget, or inflate a publisher's payout, with clicks nobody meant.
Two attackers, one per MRC tier:

    python attacks/round5_click_fraud.py          # GIVT: a flood from hosting addresses, library User-Agent,
                                                  # no Referer, no impression: identifiable by routine means
    python attacks/round5_click_fraud.py --sivt   # SIVT: dressed as a residential browser with a Referer, fires
                                                  # an impression first; its engagement funnel is hollow

The SIVT run uses six browser profiles on residential-proxy addresses (a fleet no address feed lists) and
clicks ten times per profile the instant the impression lands. It reports how many of its clicks the
store filtered under a `givt_*` tag and how many under a `sivt_*` tag (the X-Lab-Signals header).
"""

import argparse

from _common import LIB_HEADERS, LabClient, browser_headers, map_threads, report, world_pool

PROFILES, CLICKS_EACH = 6, 10


def run(clicks=60, sivt=False):
    actor = "bot:sivt" if sivt else "bot:givt"
    tally = {"counted": 0, "givt": 0, "sivt": 0}

    def record(r):
        if r.status_code == 200 and r.json().get("counted"):
            tally["counted"] += 1
            return
        tags = r.headers.get("X-Lab-Signals", "")
        tally["givt" if "givt_" in tags else "sivt" if "sivt_" in tags else "givt"] += 1

    if sivt:
        fleet = world_pool("residential_proxy_net")
        headers = browser_headers("link", "https://news.example/article", accept_json=True)

        def profile(k):
            bot = LabClient(actor, pool=fleet)
            bot.set_cookie("did", f"sivt-profile-{k}")
            bot.post("/api/ads/impression", json={"campaign": "camp-1"}, headers=headers)       # an impression, then...
            for _ in range(CLICKS_EACH):                                                         # ...instant clicks
                record(bot.post("/api/ads/click", json={"campaign": "camp-1"}, headers=headers))
        map_threads(profile, range(PROFILES))
        clicks = PROFILES * CLICKS_EACH
    else:
        def click(i):
            bot = LabClient(actor, pool=world_pool("cloud_vm"))
            record(bot.post("/api/ads/click", json={"campaign": "camp-1"}, headers=LIB_HEADERS))
        map_threads(click, range(clicks))
    return {"attacker": actor, "attempted": clicks, "succeeded": tally["counted"], "clicks_counted": tally["counted"],
            "givt_filtered": tally["givt"], "sivt_filtered": tally["sivt"], "sivt": sivt}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--clicks", type=int, default=60)
    ap.add_argument("--sivt", action="store_true")
    a = ap.parse_args()
    out = run(a.clicks, a.sivt)
    print(f"[clickfraud:{'SIVT' if a.sivt else 'GIVT'}] {out['attempted']} clicks -> {out['clicks_counted']} billed, "
          f"filtered as GIVT {out['givt_filtered']} / SIVT {out['sivt_filtered']}")
    report(**out)
