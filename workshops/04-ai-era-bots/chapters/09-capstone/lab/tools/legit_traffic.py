"""
W4 Ch9 Capstone — the legitimate-traffic mix ("measuring both sides")

Everyone the store must keep serving, run alongside every round's attack and
reported per cohort. A block of any of these is a false positive; a challenge is
friction, counted and weighted by the scoreboard.

    shoppers        people in current browsers (incl. touch, autofill, power-user,
                    a first-timer who registers during the drop)
    shared_ip       an office NAT and a procurement RPA macro behind one IP
    vpn             a person on a datacenter egress
    privacy         farbled / resistFingerprinting browsers
    a11y            screen-reader and voice-control users (accessibility API; can't see)
    agent_shopper   a person's OWN local agent, undeclared or with a UA token (the Comet case)
    cloud_signed    a vendor's cloud agent, signed by a trusted operator, with a mandate
    a11y_agent      an agent driven through the accessibility API by a disabled customer

Plus the crawlers the reservation protects:
    search          a verified, signed LabSearchBot that obeys robots.txt
    licensed_crawler a verified, signed LabTrainBot that pays the RSL price
    reader          text-mode / accessibility browsers (Lynx, w3m)
    prefetch        a browser that prefetches visible links (never hidden ones)

X-Lab-Actor labels every request; the store reads none of them.

    python tools/legit_traffic.py            # one pass, summary per cohort
"""

import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import personas  # noqa: E402
from _http_agent import run_session  # noqa: E402
from crawl import (CHROME_UA, RESIDENTIAL, SEARCHBOT_RANGE, SEARCHBOT_UA, TRAINBOT_RANGE, TRAINBOT_UA,  # noqa: E402
                   Crawler, extract_links, require_local, searchbot_signer, trainbot_signer)
from lab import BASE_URL, ensure_local  # noqa: E402

KEYS = os.path.join(LAB_DIR, "data", "keys")
LAB_OP = "agents.lab-provider.test"
READER_UAS = ["Lynx/2.9.2 libwww-FM/2.14", "w3m/0.5.3+git20230121", "ELinks/0.17.1 (textmode; Linux)"]


def _egress_for(persona, user, i):
    if persona.get("egress"):
        return persona["egress"]
    if persona.get("egress_pool") == "datacenter":
        return personas.DATACENTER[i % len(personas.DATACENTER)]
    return RESIDENTIAL[(100 + i) % len(RESIDENTIAL)]


def _shop_one(user, persona, base, i):
    """A human or agent customer: buy the drop, answer any challenge the way this cohort can."""
    egress = _egress_for(persona, user, i)
    declared = {"ua": "ua", "signed": "signed"}.get(persona.get("declared"), "none")
    mandate = None
    if persona.get("mandate"):
        from _common import grant_mandate
        mandate, _ = grant_mandate(base, user, LAB_OP, egress=egress)
    res = run_session(
        base, user, actor=f"{persona['cohort']}", egress=egress, profile=persona["profile"],
        behavior=persona["behavior"], declared=declared, operator=(LAB_OP if declared != "none" else None),
        key=(os.path.join(KEYS, "lab-provider.pem") if declared == "signed" else None),
        a11y=persona.get("a11y", False), attended=True, can_see=persona.get("can_see", True),
        mandate=mandate, register=user.get("register", False))
    res["cohort"] = persona["cohort"]
    res["persona"] = persona["name"]
    return res


def _shop_results(base, workers=5):
    by = {p["name"]: p for p in personas.PERSONAS}
    users = personas.legit_users()
    jobs = [(u, by[u["persona"]], i) for i, u in enumerate(users)]
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_shop_one, u, p, base, i) for u, p, i in jobs]
        for f in futs:
            try:
                out.append(f.result())
            except Exception as exc:  # noqa: BLE001
                out.append({"cohort": "error", "persona": "error", "outcome": "error", "reasons": [repr(exc)],
                            "challenges": [], "success": False})
    return out


def _crawler_results(base):
    out = []
    search = Crawler(base, SEARCHBOT_UA, SEARCHBOT_RANGE, actor="search", budget=30, obey_robots=True,
                     robots_token="LabSearchBot", purpose="search", follow_hidden=False,
                     signer=searchbot_signer(), label="verified LabSearchBot").crawl()
    out.append({"cohort": "search", "persona": "LabSearchBot", "rep": search,
                "outcome": "block" if search["status"].get("403") else ("maze" if search["maze_pages"] else "allow"),
                "challenges": [], "success": search["coverage"] > 0})
    lic = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, actor="licensed_crawler", budget=30, obey_robots=True,
                  robots_token="LabTrainBot", purpose="ai-train", follow_hidden=False, signer=trainbot_signer(),
                  pay={"mode": "reactive", "max": 0.05}, label="paying LabTrainBot").crawl()
    out.append({"cohort": "licensed_crawler", "persona": "LabTrainBot", "rep": lic,
                "outcome": "block" if lic["status"].get("403") else ("allow" if lic["charged_pages"] else "paywall"),
                "challenges": [], "success": lic["charged_pages"] > 0})
    for i, ua in enumerate(READER_UAS):
        c = Crawler(base, ua, [RESIDENTIAL[170 + i]], actor="reader", budget=8, obey_robots=False, follow_hidden=False,
                    browser_headers=False, label="reader").crawl()
        out.append({"cohort": "reader", "persona": f"reader-{i}", "rep": c,
                    "outcome": "maze" if c["maze_pages"] else ("block" if c["status"].get("403") else "allow"),
                    "challenges": [], "success": c["products"] > 0})
    pf = Crawler(base, CHROME_UA, [RESIDENTIAL[185]], actor="prefetch", budget=20, obey_robots=False,
                 browser_headers=True, follow_hidden=False, label="prefetch").crawl()
    out.append({"cohort": "prefetch", "persona": "prefetch", "rep": pf,
                "outcome": "maze" if pf["maze_pages"] else ("block" if pf["status"].get("403") else "allow"),
                "challenges": [], "success": pf["products"] > 0})
    return out


def run(base=BASE_URL):
    ensure_local(base)
    return _shop_results(base) + _crawler_results(base)


def summarize(results):
    by = {}
    for r in results:
        row = by.setdefault(r["cohort"], {"allow": 0, "challenge": 0, "block": 0, "maze": 0, "other": 0})
        key = r["outcome"] if r["outcome"] in row else "other"
        row[key] += 1
    return by


if __name__ == "__main__":
    import time
    t0 = time.time()
    res = run()
    print(f"=== {len(res)} legitimate customers and crawlers in {time.time() - t0:.1f} s ===")
    for cohort in personas.COHORTS + personas.CRAWLER_COHORTS:
        row = summarize(res).get(cohort)
        if not row:
            continue
        hurt = row["block"] + row["maze"]
        print(f"  {'✅' if hurt == 0 else '❌'} [{cohort:<16}] allow {row['allow']} challenge {row['challenge']} "
              f"block {row['block']} maze {row['maze']} other {row['other']}")
    for r in res:
        if r["outcome"] in ("block", "maze", "error"):
            print(f"       ❌ {r['cohort']:<14} {r['persona']:<16} {r['outcome']:<7} {r.get('reasons', [])[:2]}")
