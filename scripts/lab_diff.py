#!/usr/bin/env python3
"""
What does a lab add to its starter? File-hash diff of demo_site/, defenses/, tools/, data/.

    python scripts/lab_diff.py workshops/01-initiation/chapters/07-proof-of-work/lab
    python scripts/lab_diff.py <lab> --write-readme     # refresh the "Adds:" block between
                                                        # <!-- lab-diff:start --> and <!-- lab-diff:end --> in lab/README.md
    python scripts/lab_diff.py <lab> --shared            # assert that modules listed in lab/shared.json match their source labs

Exit 1 if the lab MODIFIED a starter file (labs may add, never edit starter files).
"""

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TREES = ["demo_site", "defenses", "tools", "data"]
IGNORE = {".venv", "instance", "__pycache__", "logs"}
ALLOWED_EDITS = {"defenses/ladder.py", "defenses/policy.py", "tools/checkpoint.py", "demo_site/templates", "README.md"}


def starter_for(lab):
    rel = os.path.relpath(lab, ROOT)
    ws = rel.split(os.sep)[1]
    return os.path.join(ROOT, "workshops", ws, "starter")


def hashes(base):
    out = {}
    for tree in TREES:
        top = os.path.join(base, tree)
        if not os.path.isdir(top):
            continue
        for root, dirs, files in os.walk(top):
            dirs[:] = [d for d in dirs if d not in IGNORE]
            for f in files:
                if f.endswith((".pyc", ".bak")):
                    continue
                p = os.path.join(root, f)
                out[os.path.relpath(p, base)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def diff(lab):
    starter = starter_for(lab)
    a, b = hashes(starter), hashes(lab)
    added = sorted(k for k in b if k not in a)
    modified = sorted(k for k in b if k in a and a[k] != b[k])
    removed = sorted(k for k in a if k not in b)
    return starter, added, modified, removed


def readme_block(added, modified):
    lines = ["<!-- lab-diff:start -->", "**Adds** (files not in the starter):", ""]
    for k in added:
        lines.append(f"- `{k}`")
    edits = [k for k in modified if any(k == e or k.startswith(e + "/") for e in ALLOWED_EDITS)]
    if edits:
        lines += ["", "**Edits** (student and tuning files):", ""] + [f"- `{k}`" for k in edits]
    lines.append("<!-- lab-diff:end -->")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lab")
    ap.add_argument("--write-readme", action="store_true")
    ap.add_argument("--shared", action="store_true")
    args = ap.parse_args()
    lab = os.path.abspath(args.lab)
    starter, added, modified, removed = diff(lab)
    print(f"starter: {os.path.relpath(starter, ROOT)}")
    print(f"added {len(added)}, modified {len(modified)}, removed {len(removed)}")
    illegal = [k for k in modified if not any(k == e or k.startswith(e + "/") for e in ALLOWED_EDITS)]
    for k in illegal:
        print(f"  MODIFIED starter file: {k}")
    for k in removed:
        print(f"  removed: {k}")
    if args.write_readme:
        p = os.path.join(lab, "README.md")
        s = open(p).read() if os.path.exists(p) else ""
        block = readme_block(added, modified)
        if "<!-- lab-diff:start -->" in s:
            s = re.sub(r"<!-- lab-diff:start -->.*?<!-- lab-diff:end -->", block, s, flags=re.S)
        else:
            s = s.rstrip() + "\n\n" + block + "\n"
        open(p, "w").write(s)
        print("README block written")
    bad = bool(illegal)
    if args.shared:
        sp = os.path.join(lab, "shared.json")
        if os.path.exists(sp):
            for rel, src in json.load(open(sp)).items():       # {"defenses/rate_limit.py": "workshops/.../02-.../lab/defenses/rate_limit.py"}
                a, b = os.path.join(lab, rel), os.path.join(ROOT, src)
                same = os.path.exists(a) and os.path.exists(b) and open(a, "rb").read() == open(b, "rb").read()
                print(f"  shared {rel}: {'same' if same else 'DIFFERS'} ({src})")
                bad = bad or not same
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
