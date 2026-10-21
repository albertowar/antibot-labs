"""
W4 Ch11 Capstone — the legitimate-traffic mix ("measuring both sides")

Everyone the store must keep serving, run alongside every round's attack and
reported per cohort. A block of any of these is a false positive; a challenge is
friction, counted and weighted by the scoreboard.

    shoppers        people in current browsers (incl. touch, autofill, power-user,
                    a first-timer who registers during the drop)
    shared_ip       an office NAT and a procurement RPA macro behind one IP
    vpn             a person on a VPN exit (a datacenter ASN)
    privacy         farbled / resistFingerprinting browsers
    a11y            screen-reader and voice-control users (accessibility API; can't see)
    agent_shopper   a person's OWN local agent, undeclared or with a UA token (the Comet case)
    cloud_signed    a vendor's cloud agent, signed by a trusted operator, with a mandate
    a11y_agent      an agent driven through the accessibility API by a disabled customer

Plus the crawlers the reservation protects, labelled `legit:` so the scoreboard's
false-positive columns and the checkpoint's legit_hurt_max judge them:

    search           a verified, signed LabSearchBot that obeys robots.txt
    licensed_crawler a verified, signed LabTrainBot that pays the RSL price
    reader           text-mode / accessibility browsers (Lynx, w3m)
    prefetch         a browser that prefetches visible links (never hidden ones)

The human cohorts carry `human:<cohort>` actor labels; X-Lab-Actor is ground
truth for the scoreboard and no defense reads it.

    python tools/legit_traffic.py            # one pass, summary per cohort
"""

import os
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, LAB_DIR)

import labclient  # noqa: E402  (runs the labnet guard on import)
import personas  # noqa: E402
from _http_agent import run_session  # noqa: E402
from crawl import (CHROME_UA, RESIDENTIAL, SEARCHBOT_RANGE, SEARCHBOT_UA, TRAINBOT_RANGE,  # noqa: E402
                   TRAINBOT_UA, Crawler, searchbot_signer, trainbot_signer)
from labclient import world_pool  # noqa: E402

BASE_URL = labclient.BASE_URL
LAB_OP = "agents.lab-provider.test"
READER_UAS = ["Lynx/2.9.2 libwww-FM/2.14", "w3m/0.5.3+git20230121", "ELinks/0.17.1 (textmode; Linux)"]

_POOL = {name: world_pool(p[0]) if len(p) == 1 else sum((world_pool(x) for x in p), [])
         for name, p in personas.EGRESS_POOLS.items()}


def _egress_for(persona, i):
    pool = _POOL[persona.get("egress_pool", "residential")]
    if persona.get("egress_pool") == "office":
        return pool[0]                      # four identical laptops behind ONE corporate IP
    return pool[(100 + i) % len(pool)]


def _shop_one(user, persona, base, i):
    """A human or agent customer: buy the drop, answer any challenge the way this cohort can."""
    egress = _egress_for(persona, i)
    declared = {"ua": "ua", "signed": "signed"}.get(persona.get("declared"), "none")
    mandate = None
    if persona.get("mandate"):
        from _common import grant_mandate
        mandate, why = grant_mandate(base, user, LAB_OP, egress=egress)
        if mandate is None:
            return {"cohort": persona["cohort"], "persona": persona["name"], "outcome": "error",
                    "reasons": [f"mandate grant failed: {why}"], "challenges": [], "success": False}
    res = run_session(
        base, user, actor=f"human:{persona['cohort']}", egress=egress, profile=persona["profile"],
        behavior=persona["behavior"], declared=declared,
        operator=(LAB_OP if declared != "none" else None), sign=(declared == "signed"),
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
    search = Crawler(base, SEARCHBOT_UA, SEARCHBOT_RANGE, actor="legit:search", budget=30, obey_robots=True,
                     robots_token="LabSearchBot", purpose="search", follow_hidden=False,
                     signer=searchbot_signer(), label="verified LabSearchBot").crawl()
    out.append({"cohort": "search", "persona": "LabSearchBot", "rep": search,
                "outcome": "block" if search["status"].get("403") else ("maze" if search["maze_pages"] else "allow"),
                "challenges": [], "success": search["coverage"] > 0})
    lic = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, actor="legit:licensed_crawler", budget=30, obey_robots=True,
                  robots_token="LabTrainBot", purpose="ai-train", follow_hidden=False, signer=trainbot_signer(),
                  pay={"mode": "reactive", "max": 0.05}, licensed=True, label="paying LabTrainBot").crawl()
    out.append({"cohort": "licensed_crawler", "persona": "LabTrainBot", "rep": lic,
                "outcome": "block" if lic["status"].get("403") else ("allow" if lic["charged_pages"] else "paywall"),
                "challenges": [], "success": lic["charged_pages"] > 0})
    for i, ua in enumerate(READER_UAS):
        c = Crawler(base, ua, [RESIDENTIAL[170 + i]], actor="legit:reader", budget=8, obey_robots=False,
                    follow_hidden=False, browser_headers=False, label="reader").crawl()
        out.append({"cohort": "reader", "persona": f"reader-{i}", "rep": c,
                    "outcome": "maze" if c["maze_pages"] else ("block" if c["status"].get("403") else "allow"),
                    "challenges": [], "success": c["products"] > 0})
    pf = Crawler(base, CHROME_UA, [RESIDENTIAL[185]], actor="legit:prefetch", budget=20, obey_robots=False,
                 browser_headers=True, follow_hidden=False, label="prefetch").crawl()
    out.append({"cohort": "prefetch", "persona": "prefetch", "rep": pf,
                "outcome": "maze" if pf["maze_pages"] else ("block" if pf["status"].get("403") else "allow"),
                "challenges": [], "success": pf["products"] > 0})
    return out


def run(base=BASE_URL):
    return _shop_results(base) + _crawler_results(base)


def summarize(results):
    by = {}
    for r in results:
        row = by.setdefault(r["cohort"], {"allow": 0, "challenge": 0, "block": 0, "maze": 0, "other": 0})
        key = r["outcome"] if r["outcome"] in row else "other"
        row[key] += 1
    return by


def run_summary(base=BASE_URL):
    """The attack-slot wrapper tools/checkpoint.py runs: one pass, cohort rows, PASS fields."""
    results = run(base)
    hurt = [r for r in results if r["outcome"] in ("block", "maze", "error")]
    return {"attempted": len(results), "succeeded": sum(1 for r in results if r["outcome"] not in
                                                        ("block", "maze", "error")),
            "cohorts": summarize(results), "hurt": [{"cohort": r["cohort"], "persona": r["persona"],
                                                     "outcome": r["outcome"], "reasons": r.get("reasons", [])[:2]}
                                                    for r in hurt]}


if __name__ == "__main__":
    import time
    t0 = time.time()
    res = run()
    print(f"=== {len(res)} legitimate customers and crawlers in {time.time() - t0:.1f} s ===")
    by = summarize(res)
    for cohort in personas.COHORTS + personas.CRAWLER_COHORTS:
        row = by.get(cohort)
        if not row:
            continue
        hurt = row["block"] + row["maze"]
        print(f"  {'✅' if hurt == 0 else '❌'} [{cohort:<16}] allow {row['allow']} challenge {row['challenge']} "
              f"block {row['block']} maze {row['maze']} other {row['other']}")
    for r in res:
        if r["outcome"] in ("block", "maze", "error"):
            print(f"       ❌ {r['cohort']:<14} {r['persona']:<16} {r['outcome']:<7} {r.get('reasons', [])[:2]}")
