#!/usr/bin/env python3
"""
Build a workshop starter: the skeleton store plus that workshop's baseline.

    python scripts/build_starter.py --workshop 2           # (re)write workshops/02-proficient/starter/
    python scripts/build_starter.py --all                  # W2, W3 and W4
    python scripts/build_starter.py --all --check          # exit 1 on drift, change nothing

The skeleton is workshops/01-initiation/starter/ (the W1 starter). It is written by hand and is
never rebuilt by this script. Every other workshop declares its starter in
workshops/<NN>/starter.manifest.json:

    {
      "workshop": 2,
      "name": "Proficient",
      "baseline": [                                   # controls always on at LADDER[0]; often empty
        {"check": "header_rules.CHECK",               # what LADDER[0] lists
         "files": {"defenses/header_rules.py": "workshops/01-initiation/chapters/04-.../lab/defenses/header_rules.py"},
         "why": "every chapter's Round 0 assumes it"}  # shown in the starter README
      ],
      "pending": [                                    # baseline controls chosen but with no starter-chain
        {"check": "...", "why": "..."}                #   source yet: documented, not installed
      ],
      "why_empty": "..."                              # README text when the baseline is empty
    }

The baselines are empty today, by decision (DECISIONS.md): every workshop runs on its own, and a
chapter that needs an earlier control at its Round 0 adds it in its own lab. The mechanism stays so
that a workshop can grow a baseline later; if one does, its starter README says what changed against
the onboarding store, and the workshop may open with a short "what's different" lesson.
"""

import argparse
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKELETON = "workshops/01-initiation/starter"
WORKSHOPS = {2: "workshops/02-proficient", 3: "workshops/03-advanced", 4: "workshops/04-ai-era-bots"}
SKIP = {".venv", "instance", "__pycache__", "logs"}

CHECKPOINT_STUB = '''"""
Round checkpoint for this lab. Declares the rounds and hands over to checkpoint_core.

The W{w} starter has no rounds: Round 0 only proves that the baseline hurts no
shopper. A chapter lab fills ROUNDS in (see checkpoint_core.Round).

    python tools/checkpoint.py --round 0
"""

from checkpoint_core import Round, main

ROUNDS = {{
    0: Round(level=0, description="{desc}", scenario="browse", bot_success_max=1.0),
}}

if __name__ == "__main__":
    main(ROUNDS)
'''


def copy_skeleton(dst):
    src = os.path.join(ROOT, SKELETON)
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        rel_root = os.path.relpath(root, src)
        for f in sorted(files):
            rel = os.path.normpath(os.path.join(rel_root, f))
            if rel in ("README.md", "STARTER.json") or f.endswith((".pyc", ".bak")):
                continue
            os.makedirs(os.path.join(dst, rel_root), exist_ok=True)
            shutil.copy2(os.path.join(root, f), os.path.join(dst, rel))
    shutil.copy2(os.path.join(ROOT, "scripts", "labnet.py"), os.path.join(dst, "labnet.py"))  # the guard, canonical


def write_ladder(dst, w, baseline):
    """LADDER[0] lists the baseline checks; the skeleton's docstring is kept."""
    path = os.path.join(dst, "defenses", "ladder.py")
    src = open(path).read()
    doc = re.match(r'("""[\s\S]*?""")', src).group(1)
    doc = doc.replace("(empty in the W1 starter)", "(this workshop's baseline)")
    checks = [b["check"] for b in baseline]
    modules = sorted({c.split(".")[0] for c in checks})
    imports = "".join(f"from . import {m}\n" for m in modules)
    if checks:
        body = f"LADDER = {{\n    0: [{', '.join(checks)}],   # the W{w} baseline (README.md says why)\n}}\n"
    else:
        body = "# from . import example_check          # 1. import the check module\nLADDER = {\n    0: [],\n    # 1: [example_check.CHECK],        # 2. wire it into a level\n}\n"
    open(path, "w").write(f"{doc}\n\n{imports}{body}")


def write_requirements(dst, w):
    path = os.path.join(dst, "requirements.txt")
    lines = open(path).read().split("\n")
    lines[0] = re.sub(r"^# W1 starter", f"# W{w} starter", lines[0])
    open(path, "w").write("\n".join(lines))


def write_readme(dst, w, ws_path, manifest, contract):
    skel = open(os.path.join(ROOT, SKELETON, "README.md")).read()
    body = skel[skel.index("## Boot it"):].replace(SKELETON, f"{ws_path}/starter")
    baseline, pending = manifest.get("baseline", []), manifest.get("pending", [])
    if baseline:
        rows = "\n".join(f"| `{b['check']}` | {b['why']} |" for b in baseline)
        base = f"`LADDER[0]` runs these on every request:\n\n| Check | Why it is in the baseline |\n|---|---|\n{rows}\n"
    else:
        base = f"None: `LADDER[0]` is empty. {manifest.get('why_empty', '')}".rstrip() + "\n"
    if pending:
        base += "\nChosen but not installed yet (no starter-chain source exists for them):\n\n"
        base += "\n".join(f"- `{p['check']}`: {p['why']}" for p in pending) + "\n"
    head = f"""# Kestrel Outfitters: the W{w} starter

**Contract:** `workshops/STORE_CONTRACT.md` (version {contract}). **Source:** the skeleton store
(`{SKELETON}/`) plus this workshop's baseline, built by `scripts/build_starter.py --workshop {w}`
from `{ws_path}/starter.manifest.json`. Do not edit this folder by hand; change the manifest and rebuild.

This folder is copied, never imported, by every Workshop {w} chapter lab. You do not need any other
workshop to run it: it is the same store the onboarding decks in the slides repo tour (`onboarding/demo-store/`), with
nothing from other chapters wired in. Do not edit it inside a lab; if a chapter needs something the
skeleton lacks, that is a contract change (see the contract's §4).

## Baseline defenses

{base}
"""
    open(os.path.join(dst, "README.md"), "w").write(head + body)


def build(w, dst):
    ws_path = WORKSHOPS[w]
    manifest = json.load(open(os.path.join(ROOT, ws_path, "starter.manifest.json")))
    assert manifest["workshop"] == w, f"{ws_path}/starter.manifest.json says workshop {manifest['workshop']}"
    contract = json.load(open(os.path.join(ROOT, SKELETON, "STARTER.json")))["contract_version"]
    os.makedirs(dst, exist_ok=True)
    copy_skeleton(dst)
    baseline = manifest.get("baseline", [])
    for b in baseline:
        for rel, src in b.get("files", {}).items():
            os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
            shutil.copy2(os.path.join(ROOT, src), os.path.join(dst, rel))
    write_ladder(dst, w, baseline)
    write_requirements(dst, w)
    desc = "baseline only: " + ", ".join(b["check"] for b in baseline) if baseline else "bare store: no defenses, every shopper buys"
    open(os.path.join(dst, "tools", "checkpoint.py"), "w").write(CHECKPOINT_STUB.format(w=w, desc=desc))
    write_readme(dst, w, ws_path, manifest, contract)
    sha = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    json.dump({"contract_version": contract, "workshop": w, "source": "skeleton+manifest", "skeleton": SKELETON,
               "manifest": f"{ws_path}/starter.manifest.json", "built_from": sha or None, "default_level": 0,
               "baseline_checks": [b["check"] for b in baseline],
               "pending_checks": [p["check"] for p in manifest.get("pending", [])],
               "description": f"The skeleton store plus the W{w} baseline."},
              open(os.path.join(dst, "STARTER.json"), "w"), indent=2)
    open(os.path.join(dst, "STARTER.json"), "a").write("\n")


def diff_trees(a, b):
    out = []
    dc = filecmp.dircmp(a, b, ignore=list(SKIP))

    def walk(d, prefix=""):
        for f in d.left_only:
            out.append(f"only in built:   {prefix}{f}")
        for f in d.right_only:
            out.append(f"only in starter: {prefix}{f}")
        for f in d.diff_files:
            out.append(f"differs:         {prefix}{f}")
        for name, sub in d.subdirs.items():
            walk(sub, prefix + name + "/")
    walk(dc)
    return [line for line in out if not line.endswith("STARTER.json")]   # built_from moves with HEAD


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--workshop", type=int, choices=sorted(WORKSHOPS))
    g.add_argument("--all", action="store_true", help="every workshop with a manifest (W2-W4)")
    ap.add_argument("--check", action="store_true", help="diff against the existing starter(s); exit 1 on drift")
    args = ap.parse_args()
    todo = sorted(WORKSHOPS) if args.all else [args.workshop]
    drift = 0
    for w in todo:
        if not os.path.exists(os.path.join(ROOT, WORKSHOPS[w], "starter.manifest.json")):
            print(f"{WORKSHOPS[w]}: no starter.manifest.json")
            drift += 1
            continue
        target = f"{WORKSHOPS[w]}/starter"
        dst = os.path.join(ROOT, target)
        with tempfile.TemporaryDirectory() as tmp:
            built = os.path.join(tmp, "built")
            build(w, built)
            if args.check:
                if not os.path.isdir(dst):
                    print(f"{target}: missing")
                    drift += 1
                    continue
                d = diff_trees(built, dst)
                print(f"{target}: {'in sync' if not d else str(len(d)) + ' differences'}")
                for line in d[:50]:
                    print("   " + line)
                drift += bool(d)
            else:
                if os.path.isdir(dst):          # keep the student's .venv and instance/
                    for name in os.listdir(dst):
                        if name not in SKIP:
                            p = os.path.join(dst, name)
                            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
                shutil.copytree(built, dst, dirs_exist_ok=True)
                print(f"wrote {target}")
    sys.exit(1 if drift else 0)


if __name__ == "__main__":
    main()
