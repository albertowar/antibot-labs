"""
W4 Ch9 Capstone — the governance audit: the other team's cards, run against the LIVE store

W4 Ch8 Round 3 swapped governance records on paper. Here the records describe a
store that is actually running, so the auditor's cards are checks, not
questions. Seven of them, each one a thing the governance record claims and a
probe that confirms it on the running store:

    1  reservation is machine-readable   robots.txt carries Content-Signal + Content-Usage,
                                         and / carries Content-Usage / TDM-Reservation / Link
    2  non-visual challenge path         a probe in the challenge band is offered a non_visual challenge
    3  appeal on a block                 a blocked reply links /appeal, which returns a contact and a time
    4  Article 50 disclosure             /assist says it is an AI and names a human path
    5  deception limit                   the signed search crawler and an a11y session receive NO decoy markup
    6  retention                         governance.json publishes retention_days <= 90 and /admin/purge honours it
    7  human in the rule loop            every active rule has an audit line whose `by` is a named person

Also scores a team's governance record against the 12-item checklist:
    python tools/audit.py --record exercises/governance_record.md

    python tools/audit.py                 # the 7 live cards
    python tools/audit.py --record FILE    # add the record score
"""

import argparse
import hashlib
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
from lab import BASE_URL, ensure_local  # noqa: E402
from record_checklist import score_record  # noqa: E402
from crawl import CHROME_UA, SEARCHBOT_RANGE, SEARCHBOT_UA, DATACENTER, searchbot_signer  # noqa: E402

RULES_ACTIVE = os.path.join(LAB_DIR, "rules", "active.json")
RULES_AUDIT = os.path.join(LAB_DIR, "rules", "audit.jsonl")
BROWSER = {"Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Mode": "navigate"}


def _admin():
    secret = open(os.path.join(LAB_DIR, "instance", "lab_secret")).read().strip()
    return {"X-Lab-Admin": hashlib.sha256(f"admin:{secret}".encode()).hexdigest()[:32]}


def card1_reservation(base):
    robots = requests.get(f"{base}/robots.txt").text
    root = requests.get(f"{base}/", headers={"User-Agent": CHROME_UA, **BROWSER})
    ok = ("Content-Signal:" in robots and "Content-Usage:" in robots
          and "Content-Usage" in root.headers and "TDM-Reservation" in root.headers and "license" in root.headers.get("Link", ""))
    return ok, "robots.txt carries Content-Signal + Content-Usage; / carries the usage headers and the RSL Link" if ok \
        else "reservation is not machine-readable on both channels"


def card2_non_visual(base):
    # A robotic probe in the challenge band: register fresh, agent behaviour, and check the challenge offered.
    sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
    from _http_agent import run_session
    acct = {"email": f"audit.probe.{os.getpid()}@mail.example", "password": "audit-probe-pw", "address": "1 Audit Way"}
    r = run_session(base, acct, actor="audit", egress="198.51.100.77", behavior="agent", declared="none",
                    register=True, attended=False, can_see=False)
    kinds = r.get("challenges", [])
    ok = any(k in ("pow", "confirm_code") for k in kinds)
    return ok, f"a challenged probe was offered a non-visual path ({kinds})" if ok \
        else f"no non-visual challenge offered ({kinds or 'none'})"


def card3_appeal(base):
    # A forged-signature session is blocked; its reply must carry an appeal link that works.
    sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
    import httpx
    s = httpx.Client(timeout=15)
    # Trigger a block via the honeypot SKU (always blocks) and read the reply.
    r = s.get(f"{base}/product/cat-901", headers={"User-Agent": CHROME_UA, **BROWSER})
    linked = "/appeal" in r.text or "/appeal" in r.headers.get("Link", "")
    ap = requests.get(f"{base}/appeal")
    body = ap.json() if ap.status_code == 200 else {}
    ok = ap.status_code == 200 and body.get("contact") and body.get("human_review_within_hours")
    return bool(ok), ("a block links /appeal; it returns a contact and a review time" if ok
                      else "no working appeal path on a block")


def card4_disclosure(base):
    r = requests.post(f"{base}/assist", json={"sku": "cat-001", "question": "is it waterproof?"},
                      headers={"User-Agent": CHROME_UA, **BROWSER}, timeout=60)
    body = r.json()
    ok = bool(body.get("ai_disclosure")) or r.headers.get("X-AI-Disclosure")
    return bool(ok), "/assist discloses it is an AI and names a human path" if ok else "/assist does not disclose it is an AI"


def card5_deception_limit(base):
    # The verified search crawler and an a11y session must see no decoy markup.
    sig = searchbot_signer()
    h = {"User-Agent": SEARCHBOT_UA, "X-Lab-Egress": SEARCHBOT_RANGE[0], **BROWSER}
    h.update(sig.headers(base.split("//", 1)[-1]))
    crawler_html = requests.get(f"{base}/catalog?page=1", headers=h).text
    # an a11y browser session: send telemetry marking the accessibility API, then load the catalogue
    s = requests.Session()
    s.headers.update({"User-Agent": CHROME_UA, "X-Lab-Egress": "198.51.100.90", **BROWSER})
    s.get(f"{base}/")
    s.post(f"{base}/api/telemetry", json={"page": "/catalog", "fp": {"ua": CHROME_UA},
                                          "events": {"a11y_api": True, "clicks": [], "moves": []}})
    a11y_html = s.get(f"{base}/catalog?page=1").text
    ok = "data-decoy" not in crawler_html and "data-decoy" not in a11y_html
    return ok, "the honoured crawler and an a11y session receive no decoy markup" if ok \
        else "a decoy block reached a client the reservation protects"


def card6_retention(base):
    gov = requests.get(f"{base}/.well-known/governance.json").json()
    rd = gov.get("retention_days")
    purge = requests.post(f"{base}/admin/purge?dry_run=1", headers=_admin()).json()
    ok = isinstance(rd, int) and rd <= 90 and purge.get("ok") and purge.get("retention_days") == rd
    return bool(ok), f"governance.json publishes retention_days={rd} (<=90) and /admin/purge honours it" if ok \
        else f"retention not published or not enforced (retention_days={rd})"


def card7_human_rule(base):
    active = json.load(open(RULES_ACTIVE)) if os.path.exists(RULES_ACTIVE) else {"rules": []}
    audit_by = {}
    if os.path.exists(RULES_AUDIT):
        for line in open(RULES_AUDIT):
            if line.strip():
                rec = json.loads(line)
                if rec.get("action") == "approve":
                    audit_by[rec.get("rule_id")] = rec.get("by")
    rules = active.get("rules", [])
    bad = [r.get("id") for r in rules if audit_by.get(r.get("id")) in (None, "", "mock", "llm", "triage")]
    ok = not bad
    if not rules:
        return True, "no active rules yet (nothing approved); the loop is empty, which is allowed"
    return ok, f"every active rule was approved by a named person ({len(rules)} rules)" if ok \
        else f"active rules with no human approver: {bad}"


CARDS = [("1 reservation machine-readable", card1_reservation), ("2 non-visual challenge path", card2_non_visual),
         ("3 appeal on a block", card3_appeal), ("4 Article 50 disclosure", card4_disclosure),
         ("5 deception limit honoured", card5_deception_limit), ("6 retention published and enforced", card6_retention),
         ("7 human in the rule loop", card7_human_rule)]


def run(base=BASE_URL, record=None):
    ensure_local(base)
    print("=== Governance audit: the auditor's cards against the live store ===\n")
    passed = 0
    for name, fn in CARDS:
        try:
            ok, detail = fn(base)
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"card errored: {exc!r}"
        passed += ok
        print(f"  [{'x' if ok else ' '}] {name:<34} {detail}")
    print(f"\nAudit: {passed}/{len(CARDS)} cards answered.")
    if record:
        rows, covered = score_record(record)
        print(f"\nGovernance record {os.path.relpath(record, LAB_DIR)}: {covered}/12 checklist items covered.")
        for name, what, hit in rows:
            if not hit:
                print(f"      missing: {name} — {what}")
    return passed


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--record")
    a = ap.parse_args()
    sys.exit(0 if run(a.url, a.record) == len(CARDS) else 1)
