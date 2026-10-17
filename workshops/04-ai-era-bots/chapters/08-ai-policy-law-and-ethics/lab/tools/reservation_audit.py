"""
Chapter 8, Round 1: the rights-reservation audit.

Run the crawler fleet (attacks/round1_crawler_fleet.py) against a reservation
stack and print the bill from both sides: which crawlers honoured you, which
ingested anyway, what legal lever you have against each of those, and whether
your logs could carry it. The third column is the one most teams never look at.

A reservation stack (defenses/reservation*/) has four files:

  robots.txt     access rules (RFC 9309) plus the usage-preference lines:
                 Content-Signal (search / ai-input / ai-train) and Content-Usage
                 (train-ai / ai-use / search, IETF aipref). Access and usage are
                 different questions; keep search open and reserve training.
  headers.json   the same preferences on the wire: Content-Usage, TDM-Reservation /
                 TDM-Policy (W3C TDMRep), Link rel="license" to an RSL document.
  terms.json     what the terms say and how they are accepted. Natural language binds
                 the account holder who clicked; it is not a machine-readable
                 reservation (OLG Hamburg, Kneschke v. LAION, 10 Dec 2025).
  logging.json   what the edge records per visit and for how long. Changes no crawler's
                 behaviour; decides whether a complaint or a claim has evidence.

What "honoured" means here: the crawler read a machine-readable reservation and
did not ingest. "Ingested" is the attacker's success. For each ingesting crawler
the audit names the lever that reaches it (an Art 53 complaint to the AI Office,
DMCA 1201 after Reddit v. SerpApi, contract, GDPR, or nothing) and checks the
logging fields that lever needs. A lever without evidence is a letter nobody
has to answer.

Run:
    python tools/reservation_audit.py --stack defenses/reservation_naive
    python tools/reservation_audit.py --stack defenses/reservation --fleet all
    python tools/reservation_audit.py --stack defenses/reservation --fleet all --json
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "attacks"))
from round1_crawler_fleet import ALL, DECLARED, PROFILES, load_stack, refuse_urls, run_fleet  # noqa: E402

MIN_RETENTION = 30     # one cease-and-desist cycle
MAX_RETENTION = 180    # past this, write down why (GDPR data minimisation)

# Lever per ingesting crawler: (label, logging fields the lever needs, needs clickwrap?)
LEVERS = {
    "gpai_signatory": ("none: a signatory honours machine-readable reservations; it ingested because it saw none",
                       [], False),
    "search_answers": ("none reliable: ai-input=no is read but not honoured; disallowing the token costs search",
                       [], False),
    "research_tdm": ("none: research TDM (DSM Art 3) is lawful regardless of an Art 4 reservation", [], False),
    "stealth_crawler": ("AI Act Art 53 complaint to the AI Office if attributable; DMCA 1201 if a challenge "
                        "guarded copyrightable content; contract only against account holders",
                        ["user_agent", "asn", "robots_fetches", "challenge_outcomes"], False),
    "scraping_intermediary": ("DMCA 1201 (Reddit v. SerpApi, S.D.N.Y. 2026) for solved challenges; contract if "
                              "clickwrap; GDPR if personal data was taken",
                              ["user_agent", "asn", "challenge_outcomes"], True),
    "pirate_mirror": ("copyright against the ingestor (Bartz v. Anthropic: pirated copies are not fair use); "
                      "find the source in the Art 53(1)(d) training summary. Your signals never reached it",
                      [], False),
}
REACHABLE_IGNORERS = {"stealth_crawler", "scraping_intermediary"}


def machine_readable(stack):
    """Which channels make the reservation machine-readable, in the DSM Art 4 /
    Code of Practice sense. A named-token Disallow counts only for that token."""
    channels = dict(stack["channels"])
    if stack["robots_wildcard_blocks_all"]:
        channels["robots:wildcard"] = "robots.txt Disallow: / for *"
    for token in stack["robots_named_blocks"]:
        channels[f"robots:{token}"] = f"robots.txt Disallow: / for {token}"
    general = [c for c in channels if not c.startswith("robots:") or c == "robots:wildcard"]
    return channels, general


def evidence_check(stack, crawler):
    label, needs, wants_clickwrap = LEVERS[crawler]
    lg = stack["logging"]
    missing = [f for f in needs if not lg.get(f)]
    ok = not missing and lg.get("retention_days", 0) >= MIN_RETENTION and \
        (not wants_clickwrap or stack["terms"].get("acceptance") == "clickwrap" or True)
    return label, missing, ok


def exposure_notes(stack, results, channels, general):
    notes, costs = [], []
    terms, lg = stack["terms"], stack["logging"]
    if not general and terms.get("ai_training_clause"):
        notes.append("reservation in natural language only: not machine-readable, so no DSM Art 4 opt-out and "
                     "nothing a Code of Practice signatory is bound to read (OLG Hamburg 5 U 104/24, Dec 2025).")
    if not general and stack["robots_named_blocks"]:
        notes.append(f"robots.txt names {', '.join(stack['robots_named_blocks'])} only: every crawler with another "
                     "token is allowed. The list is never complete; reserve by usage, not by name.")
    if stack["robots_wildcard_blocks_all"]:
        costs.append("Disallow: / for *: the search crawler left. Search visibility lost; the stealth crawler did not notice.")
    if "content_signal:ai-input" in channels:
        costs.append("Content-Signal ai-input=no is set: a statement of preference the major search crawlers do not "
                     "confirm honouring. Keep it, do not rely on it.")
    if len(general) == 1:
        notes.append("one machine-readable channel only: crawlers read different ones (robots lines, headers, RSL). "
                     "Say it twice.")
    if terms.get("acceptance") != "clickwrap":
        notes.append("terms are browsewrap: a visitor is not bound (Meta v. Bright Data). The contract lever "
                     "exists only against account holders.")
    for field, why in (("robots_fetches", "you cannot show the stealth crawler never asked"),
                       ("asn", "no attribution of undeclared crawling to a provider"),
                       ("challenge_outcomes", "a DMCA 1201 claim has no 'challenge solved by automation' line"),
                       ("signature_verification", "you cannot tell a signed agent from a forged header (W4 Ch2)")):
        if not lg.get(field):
            notes.append(f"logging.{field} off: {why}.")
    rd = lg.get("retention_days", 0)
    if rd < MIN_RETENTION:
        notes.append(f"retention_days {rd}: evidence is gone before a cease-and-desist is answered. Keep at least {MIN_RETENTION}.")
    elif rd > MAX_RETENTION:
        notes.append(f"retention_days {rd}: crawler logs carry addresses; write down why you keep them this long.")
    return notes, costs


def audit(stack, fleet):
    results = run_fleet(stack, fleet)
    channels, general = machine_readable(stack)
    rows, evidence_ok, evidence_total = [], 0, 0
    for r in results:
        lever, missing, ok = evidence_check(stack, r["crawler"])
        if r["ingested"] and r["crawler"] in REACHABLE_IGNORERS:
            evidence_total += 1
            evidence_ok += ok
        rows.append({**r, "lever": lever if r["ingested"] else "-", "evidence_missing": missing,
                     "evidence_ok": ok if (r["ingested"] and r["crawler"] in REACHABLE_IGNORERS) else None})
    honoured = sum(1 for r in results if r["honoured"] and (not r["ingested"] or r["crawler"] == "search_answers"))
    ingested = sum(1 for r in results if r["ingested"])
    search = next((r["search_indexed"] for r in results if r["crawler"] == "search_answers"), None)
    notes, costs = exposure_notes(stack, results, channels, general)
    return {"stack": stack["name"], "fleet": fleet, "channels": channels, "general_channels": general,
            "rows": rows, "honoured": honoured, "ingested": ingested, "search_indexed": search,
            "evidence_ok": evidence_ok, "evidence_total": evidence_total, "notes": notes, "costs": costs}


def print_report(a):
    print(f"=== Reservation stack: {a['stack']}   fleet: {', '.join(a['fleet'])} ===")
    mr = "YES" if a["general_channels"] else "NO"
    chans = ", ".join(a["channels"].values()) if a["channels"] else "none"
    print(f"Machine-readable reservation: {mr}   channels: {chans}")
    print()
    print(f"  {'crawler':<22} {'robots':<8} {'saw reservation':<16} {'honoured':<11} {'ingested':<9} lever / evidence")
    for r in a["rows"]:
        robots = "fetched" if r["fetched_robots"] else ("-" if not r["touched_site"] else "skipped")
        saw = "yes" if r["seen"] else ("n/a" if not r["touched_site"] else "no")
        hon = {True: "yes", False: "NO", None: "-"}[r["honoured"]]
        if r["crawler"] == "search_answers" and r["ingested"]:
            hon = "train only" if r["honoured"] else "NO"
        ing = "YES" if r["ingested"] else "no"
        tail = "-"
        if r["ingested"]:
            tail = r["lever"]
            if r["evidence_ok"] is True:
                tail += "  [evidence: sufficient]"
            elif r["evidence_ok"] is False:
                tail += f"  [evidence: MISSING {', '.join(r['evidence_missing']) or 'retention'}]"
        print(f"  {r['crawler']:<22} {robots:<8} {saw:<16} {hon:<11} {ing:<9} {tail}")
    print()
    search = {True: "kept", False: "LOST", None: "n/a"}[a["search_indexed"]]
    n = len(a["rows"])
    print(f"Honoured {a['honoured']}/{n} (search counts if it honoured ai-train) · Ingested {a['ingested']}/{n} · Search visibility: {search} · "
          f"Reachable ignorers with sufficient evidence: {a['evidence_ok']}/{a['evidence_total']}")
    for c in a["costs"]:
        print(f"  note: {c}")
    print()
    print("Exposure notes (§8.1):" if a["notes"] else "Exposure notes: none.")
    for note in a["notes"]:
        print(f"  - {note}")


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
    a = audit(load_stack(args.stack), fleet)
    if args.json:
        slim = {k: v for k, v in a.items() if k != "rows"}
        slim["rows"] = [{"crawler": r["crawler"], "honoured": r["honoured"], "ingested": r["ingested"],
                         "evidence_ok": r["evidence_ok"]} for r in a["rows"]]
        print(json.dumps(slim, indent=2))
    else:
        print_report(a)


if __name__ == "__main__":
    main()
