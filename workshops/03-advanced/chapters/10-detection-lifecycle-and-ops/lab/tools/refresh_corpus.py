"""
Refresh the data the sensors depend on (Round 2)

The ASN database, the header-order corpus and the JA4 table are data with a
date. This is the nightly job that pulls the new versions, written to
data/world_updates.json and hot-reloaded by defenses/corpus.py (netinfo, sensor_headers, sensor_tls).

    python tools/refresh_corpus.py --show
    python tools/refresh_corpus.py --asn                   learn the reassigned range (week 3's fix)
    python tools/refresh_corpus.py --browser chrome        learn Chrome 146's order and JA4
    python tools/refresh_corpus.py --all --week 3          everything, stamped as refreshed in week 3
    python tools/refresh_corpus.py --reset

In production you do not type these; a scheduler runs them and a freshness
gauge pages you when it has not (tools/drift.corpus_ages, the
corpus_age_weeks metric). The lab makes the refresh a command so you can see
exactly which stale fact was hurting which customers before and after.
"""

import argparse
import sys

import report as _lab  # noqa: F401,E402  (puts the lab root on sys.path)
from defenses import corpus  # noqa: E402
from personas_ch10 import JA4_CHROME_NEW, REASSIGNED_POOL, REASSIGNED_RANGE  # noqa: E402

# The world moved; this is what a refreshed feed would now say.
REASSIGNED = {REASSIGNED_RANGE: REASSIGNED_POOL}      # Example Fiber bought it from Example Cloud
CHROME_146_ORDER = ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
                    "sec-fetch-mode", "sec-fetch-dest", "user-agent", "accept", "origin",
                    "referer", "accept-encoding", "accept-language"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--asn", action="store_true")
    parser.add_argument("--browser", choices=["chrome"], help="learn a new browser release")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--week", type=int, default=3, help="stamp the refresh as happening this week")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    if args.reset:
        corpus.clear()
        print("corpus updates cleared; the sensors are back to the week-0 snapshot")
        return 0
    data = dict(corpus.updates())
    data.setdefault("refreshed_week", {})
    if args.asn or args.all:
        data.setdefault("reassigned", {}).update(REASSIGNED)
        data["refreshed_week"]["asn_database"] = args.week
        print(f"asn: learned {REASSIGNED} (refreshed week {args.week})")
    if args.browser == "chrome" or args.all:
        data.setdefault("header_order", {}).setdefault("chrome", [])
        if CHROME_146_ORDER not in data["header_order"]["chrome"]:
            data["header_order"]["chrome"].append(CHROME_146_ORDER)
        data.setdefault("ja4", {})["chrome-146"] = JA4_CHROME_NEW
        data["refreshed_week"]["header_order"] = args.week
        data["refreshed_week"]["ja4_table"] = args.week
        print(f"browser: learned Chrome 146's header order and JA4 (refreshed week {args.week})")
    if not args.show and (args.asn or args.browser or args.all):
        corpus.write(data)
    print("\ncurrent corpus updates (data/world_updates.json):")
    print(f"  refreshed_week: {data.get('refreshed_week', {})}")
    print(f"  reassigned: {data.get('reassigned', {})}")
    print(f"  knows Chrome 146: {'chrome-146' in data.get('ja4', {})}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
