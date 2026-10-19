"""
W4 Ch10 Capstone — human approval: onboarding a trusted agent operator (Round 4)

Launch day's drift: a new vendor's agent (agents.newvendor.test) is honest,
signed and carries a mandate, but the store has never heard of it, so agent
governance refuses it (a valid signature from an unknown origin is identity, not
entitlement — W4 Ch2). Trusting an operator is a business decision a *person*
makes, never the model: this tool is how they make it, writing the origin into
rules/trusted_operators.json, which defenses/policy.TRUSTED_AGENTS reads live
(POST /lab/reset restores the seed). Every onboarding is stamped with who did it.

Rule drafting and approval — triage proposing a detection rule, the gate testing
it against the shopper cohorts, a person approving it — is the subject of W4 Ch7
and is not repeated here; the capstone's human-in-the-loop action is onboarding.

    python tools/approve.py --list
    python tools/approve.py onboard-operator --origin https://agents.newvendor.test --by alice
    python tools/approve.py onboard-operator --origin https://agents.newvendor.test --by alice \
        --category "shopping-agent vendor"
"""

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
TRUSTED = os.path.join(LAB, "rules", "trusted_operators.json")


def _load():
    if os.path.exists(TRUSTED):
        try:
            with open(TRUSTED) as fh:
                doc = json.load(fh)
        except (ValueError, OSError):
            doc = {}
    else:
        doc = {}
    doc.setdefault("trusted", {})
    return doc


def _save(doc):
    os.makedirs(os.path.dirname(TRUSTED), exist_ok=True)
    tmp = TRUSTED + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, TRUSTED)


def onboard(origin, by, category):
    if not origin.startswith("https://"):
        raise SystemExit("origin must be an https:// Signature-Agent origin, e.g. https://agents.newvendor.test")
    if not by:
        raise SystemExit("--by <name>: an onboarding is a decision a named person makes")
    doc = _load()
    doc["trusted"][origin] = {"category": category, "by": by,
                              "onboarded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _save(doc)
    print(f"onboarded {origin} as '{category}' (by {by}). Trusted operators now: "
          + ", ".join(sorted(doc["trusted"])))


def list_onboarded():
    doc = _load()
    if not doc["trusted"]:
        print("no operators onboarded at runtime (the seed in defenses/policy.py is still the whole trust set)")
        return
    for origin, rec in sorted(doc["trusted"].items()):
        print(f"  {origin}  {rec.get('category', '?')}  (by {rec.get('by', '?')} at {rec.get('onboarded_at', '?')})")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd")
    on = sub.add_parser("onboard-operator")
    on.add_argument("--origin", required=True)
    on.add_argument("--by", required=True)
    on.add_argument("--category", default="agent operator")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.cmd == "onboard-operator":
        onboard(args.origin, args.by, args.category)
    elif args.list:
        list_onboarded()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
