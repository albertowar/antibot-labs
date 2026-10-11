"""
Chapter 8, Round 1: the crawler fleet, run against your reservation stack.

Nothing here touches a network. Each profile below is a model of how one kind
of AI-era crawler behaves when it meets the files in defenses/reservation/:
whether it fetches robots.txt, which signals it reads, which it honours, and
what it does when it decides to ingest anyway. The models are drawn from
public behaviour as of October 2026 (the GPAI Code of Practice copyright
chapter, Cloudflare's reports on undeclared crawling, the aipref and TDMRep
specs); they are types, not vendors, and the user-agent tokens are invented.

    gpai_signatory        a training crawler run by a GPAI Code of Practice signatory.
                          Fetches robots.txt, honours any machine-readable reservation it
                          can find, ignores natural-language terms (the Code does not count
                          them, and after OLG Hamburg 2025 neither does the DSM opt-out).
    search_answers        the search engine's crawler that also feeds AI answers. Honours
                          robots rules for its token and the ai-train signal; the ai-input
                          signal is contested and it does not act on it. Disallowing its token
                          removes you from search, not just from the answers.
    research_tdm          a university TDM crawler (EU DSM Directive Art 3). Fetches
                          robots.txt and respects Disallow as politeness, but an Art 4
                          reservation has no legal effect on research TDM.
    stealth_crawler       never fetches robots.txt, sends a Chrome user agent, rotates cloud
                          ASNs outside any published range, and ingests everything.
    scraping_intermediary a scraping-as-a-service vendor. Declares a token sometimes,
                          fetches robots.txt, ignores it, solves your challenges, resells.
    pirate_mirror         never visits you. Ingests a copy of your catalogue from a mirror or
                          a shadow dataset. No signal you emit reaches it.

Run (defaults to the three declared crawlers; --fleet all adds the rest):
    python attacks/round1_crawler_fleet.py --stack defenses/reservation
    python attacks/round1_crawler_fleet.py --stack defenses/reservation --fleet all

Ethics: this script reads local files only and refuses anything that looks
like a URL. The real versions of these crawlers are other people's
infrastructure; model them, do not run them.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)

DECLARED = ["gpai_signatory", "search_answers", "research_tdm"]
ALL = DECLARED + ["stealth_crawler", "scraping_intermediary", "pirate_mirror"]

PROFILES = {
    "gpai_signatory": {
        "ua": "GPAI-Crawler", "purpose": "train", "touches_site": True, "fetches_robots": True,
        "reads": {"robots", "content_signal:ai-train", "content_usage:train-ai", "tdm_header", "rsl_link"},
        "honours_what_it_reads": True, "declared": True, "attributable": True,
    },
    "search_answers": {
        "ua": "SearchBot", "purpose": "answers", "touches_site": True, "fetches_robots": True,
        "reads": {"robots", "content_signal:ai-train", "content_usage:train-ai"},
        "honours_what_it_reads": True, "declared": True, "attributable": True,
    },
    "research_tdm": {
        "ua": "UniTDM-Research", "purpose": "research", "touches_site": True, "fetches_robots": True,
        "reads": {"robots"}, "honours_what_it_reads": True, "declared": True, "attributable": True,
    },
    "stealth_crawler": {
        "ua": "Mozilla/5.0 (Macintosh) Chrome/141", "purpose": "train", "touches_site": True,
        "fetches_robots": False, "reads": set(), "honours_what_it_reads": False, "declared": False,
        "attributable": False,
    },
    "scraping_intermediary": {
        "ua": "ScrapeFeed-Bot", "purpose": "resale", "touches_site": True, "fetches_robots": True,
        "reads": {"robots"}, "honours_what_it_reads": False, "declared": True, "attributable": True,
    },
    "pirate_mirror": {
        "ua": None, "purpose": "train", "touches_site": False, "fetches_robots": False,
        "reads": set(), "honours_what_it_reads": False, "declared": False, "attributable": False,
    },
}


# ---------- parsing the stack ----------

def parse_robots(text):
    """A small RFC 9309 reader: groups of User-agent lines with Allow/Disallow rules,
    plus the two usage-preference lines (Content-Signal, Content-Usage) wherever they
    appear. Enough for the fleet; not a replacement for a real parser."""
    groups, current, signal, usage = [], None, {}, {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = [p.strip() for p in line.split(":", 1)]
        key = key.lower()
        if key == "user-agent":
            if current is None or current["rules"]:
                current = {"agents": [], "rules": []}
                groups.append(current)
            current["agents"].append(value.lower())
        elif key in ("allow", "disallow") and current is not None:
            current["rules"].append((key, value))
        elif key == "content-signal":
            signal.update(_kv(value))
        elif key == "content-usage":
            usage.update(_kv(value))
    return {"groups": groups, "content_signal": signal, "content_usage": usage}


def _kv(value):
    out = {}
    for part in value.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def robots_group_for(robots, token):
    """RFC 9309: the most specific matching group wins; '*' is the fallback."""
    token = token.lower()
    for g in robots["groups"]:
        if token in g["agents"]:
            return g, "named"
    for g in robots["groups"]:
        if "*" in g["agents"]:
            return g, "wildcard"
    return None, None


def robots_blocks_everything(group):
    return group is not None and any(k == "disallow" and v.strip() == "/" for k, v in group["rules"])


def load_stack(path):
    def read_json(name):
        with open(os.path.join(path, name)) as f:
            return json.load(f)
    with open(os.path.join(path, "robots.txt")) as f:
        robots = parse_robots(f.read())
    headers = {k.lower(): v for k, v in read_json("headers.json").get("headers", {}).items()}
    terms = read_json("terms.json")
    logging = read_json("logging.json")
    channels = {}
    if robots["content_signal"].get("ai-train") == "no":
        channels["content_signal:ai-train"] = "robots.txt Content-Signal ai-train=no"
    if robots["content_signal"].get("ai-input") == "no":
        channels["content_signal:ai-input"] = "robots.txt Content-Signal ai-input=no"
    usage = dict(robots["content_usage"])
    usage.update(_kv(headers.get("content-usage", "")))
    if usage.get("train-ai") == "n":
        channels["content_usage:train-ai"] = "Content-Usage train-ai=n (aipref)"
    if usage.get("ai-use") == "n":
        channels["content_usage:ai-use"] = "Content-Usage ai-use=n (aipref)"
    if str(headers.get("tdm-reservation", "")).strip() == "1":
        channels["tdm_header"] = "TDM-Reservation: 1 (TDMRep)"
    if 'rel="license"' in headers.get("link", "") and "rsl" in headers.get("link", "").lower():
        channels["rsl_link"] = "Link rel=license (RSL)"
    named = sorted(a for g in robots["groups"] for a in g["agents"] if a != "*" and robots_blocks_everything(g))
    wildcard_group, _ = robots_group_for(robots, "__nobody__")
    return {
        "name": os.path.basename(os.path.normpath(path)),
        "robots": robots, "headers": headers, "terms": terms, "logging": logging,
        "channels": channels, "robots_named_blocks": named,
        "robots_wildcard_blocks_all": robots_blocks_everything(wildcard_group),
        "robots_has_wildcard_group": wildcard_group is not None,
    }


# ---------- the fleet ----------

def visit(name, stack):
    """One crawler meets the stack. Returns what it saw and what it did."""
    p = PROFILES[name]
    out = {"crawler": name, "ua": p["ua"], "purpose": p["purpose"], "touched_site": p["touches_site"],
           "fetched_robots": False, "robots_match": None, "seen": [], "honoured": None, "ingested": True,
           "declared": p["declared"], "attributable": p["attributable"], "logged": [], "search_indexed": None}
    if not p["touches_site"]:
        out["ingested"] = True
        return out
    # what the edge logged about this visit, given logging.json
    lg = stack["logging"]
    for field in ("user_agent", "asn", "robots_fetches", "challenge_outcomes", "signature_verification"):
        if lg.get(field):
            out["logged"].append(field)
    seen = []
    if p["fetches_robots"]:
        out["fetched_robots"] = True
        group, how = robots_group_for(stack["robots"], p["ua"] or "")
        out["robots_match"] = how
        if "robots" in p["reads"] and robots_blocks_everything(group):
            seen.append(f"robots.txt Disallow: / ({how} group)")
        for ch in ("content_signal:ai-train", "content_usage:train-ai"):
            if ch in p["reads"] and ch in stack["channels"]:
                seen.append(stack["channels"][ch])
    for ch in ("tdm_header", "rsl_link"):
        if ch in p["reads"] and ch in stack["channels"]:
            seen.append(stack["channels"][ch])
    out["seen"] = seen
    if name == "search_answers":
        group, how = robots_group_for(stack["robots"], p["ua"])
        out["search_indexed"] = not robots_blocks_everything(group)
        # Training: honours the ai-train signals and a Disallow. Answers: only a Disallow stops it,
        # and that also removes you from search. ai-input=no is read but not acted on (contested).
        if not out["search_indexed"]:
            out["honoured"], out["ingested"] = True, False
        else:
            train_signal = any(s.startswith(("robots.txt Content-Signal ai-train", "Content-Usage train-ai")) for s in seen)
            out["honoured"] = train_signal
            out["ingested"] = True          # still ingests for answers
            out["ignored_contested"] = "content_signal:ai-input" in stack["channels"]
        return out
    if seen and p["honours_what_it_reads"]:
        out["honoured"], out["ingested"] = True, False
    elif seen:
        out["honoured"], out["ingested"] = False, True
    else:
        out["honoured"], out["ingested"] = None, True
    return out


def run_fleet(stack, fleet):
    return [visit(name, stack) for name in fleet]


def refuse_urls(value):
    if re.match(r"^\w+://", value or ""):
        sys.exit("This fleet runs against local files only. It will not take a URL.")
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stack", default=os.path.join(LAB, "defenses", "reservation"))
    ap.add_argument("--fleet", default="declared", help="'declared' (default), 'all', or a comma list")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    refuse_urls(args.stack)
    fleet = ALL if args.fleet == "all" else DECLARED if args.fleet == "declared" else args.fleet.split(",")
    unknown = [c for c in fleet if c not in PROFILES]
    if unknown:
        ap.error(f"unknown crawler(s) {unknown}; choose from {ALL}")
    stack = load_stack(args.stack)
    results = run_fleet(stack, fleet)
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print(f"=== Crawler fleet vs stack '{stack['name']}' ({len(fleet)} crawlers): the attacker's view ===\n")
    for r in results:
        if not r["touched_site"]:
            print(f"[{r['crawler']}] never visited. Ingested your catalogue from a mirror. Saw none of your signals.")
            continue
        robots = ("fetched robots.txt, matched the " + (r["robots_match"] or "no") + " group") if r["fetched_robots"] \
            else "did not fetch robots.txt"
        seen = ", ".join(r["seen"]) if r["seen"] else "nothing it recognises"
        if r["crawler"] == "search_answers":
            did = ("left: not indexed, not used for answers" if not r["ingested"] else
                   "indexed you" + (" and will not train on you" if r["honoured"] else " and may train on you")
                   + "; used your pages for AI answers anyway" + (" (ai-input=no read, not acted on)" if r.get("ignored_contested") else ""))
        elif r["ingested"]:
            did = "ingested everything" + (" despite the reservation" if r["seen"] else "")
        else:
            did = "honoured the reservation and left"
        print(f"[{r['crawler']}] UA '{r['ua']}': {robots}; saw: {seen}; {did}.")
        print(f"    what you logged about this visit: {', '.join(r['logged']) or 'nothing'}"
              f" (kept {stack['logging'].get('retention_days', 0)} days)")
    ingested = sum(1 for r in results if r["ingested"])
    print(f"\nIngested: {ingested}/{len(results)}. Now run tools/reservation_audit.py for the legal scoreboard.")


if __name__ == "__main__":
    main()
