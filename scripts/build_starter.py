#!/usr/bin/env python3
"""
Build a workshop starter from a capstone lab's end state.

    python scripts/build_starter.py --from workshops/01-initiation/chapters/09-mini-capstone/lab
    python scripts/build_starter.py --from <capstone lab> --check      # exit 1 on drift, change nothing

The capstone lab declares what "end state" means in starter.manifest.json:

    {
      "targets": ["workshops/02-proficient/starter"],       # one or more (W2 Ch9 -> W3 and W4)
      "contract_version": "1.0",
      "overlay_rounds": 5,                                   # apply solutions/round1..N cumulatively
      "flatten_ladder": true,                                # LADDER levels 1..N fold into level 0
      "include": ["demo_site", "defenses", "tools", "data", "docker-compose.yml", "requirements.txt",
                  "requirements-browser.txt", ".env.example", ".gitignore"],
      "exclude": ["attacks/*.py", "solutions", "instance", "logs", "**/__pycache__", "**/*.bak",
                  "tools/checkpoint.py", "tools/personas_*.py", "tools/drop.py"],
      "readme": "starter.README.md"                          # optional README to ship in the target
    }

The result is the capstone's tree with every solution installed, chapter-only files removed, the
ladder flattened (what the capstone enforced at its last level becomes the next workshop's baseline),
tools/checkpoint.py reset to a Round 0 stub, and STARTER.json recording provenance.
"""

import argparse
import filecmp
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CHECKPOINT_STUB = '''"""
Round checkpoint for this lab. Declares the rounds and hands over to checkpoint_core.

This starter has no rounds: Round 0 proves the inherited baseline hurts no shopper.
A chapter lab fills ROUNDS in (see checkpoint_core.Round).

    python tools/checkpoint.py --round 0
"""

from checkpoint_core import Round, main

ROUNDS = {
    0: Round(level=0, description="baseline inherited from the previous workshop", scenario="browse", bot_success_max=1.0),
}

if __name__ == "__main__":
    main(ROUNDS)
'''


def excluded(rel, patterns):
    parts = rel.split(os.sep)
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat.replace("**/", "")) for p in parts) or rel.startswith(pat.rstrip("/") + os.sep) or rel == pat:
            return True
    return False


def copy_tree(src_lab, manifest, dst):
    for item in manifest["include"]:
        src = os.path.join(src_lab, item)
        if not os.path.exists(src):
            continue
        if os.path.isdir(src):
            for root, dirs, files in os.walk(src):
                rel_root = os.path.relpath(root, src_lab)
                dirs[:] = [d for d in dirs if not excluded(os.path.join(rel_root, d), manifest["exclude"])]
                for f in files:
                    rel = os.path.join(rel_root, f)
                    if excluded(rel, manifest["exclude"]):
                        continue
                    os.makedirs(os.path.join(dst, rel_root), exist_ok=True)
                    shutil.copy2(os.path.join(root, f), os.path.join(dst, rel))
        else:
            shutil.copy2(src, os.path.join(dst, item))


def overlay_solutions(src_lab, dst, rounds):
    for n in range(1, rounds + 1):
        sdir = os.path.join(src_lab, "solutions", f"round{n}")
        if not os.path.isdir(sdir):
            continue
        for root, _, files in os.walk(sdir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), sdir)
                os.makedirs(os.path.dirname(os.path.join(dst, rel)) or dst, exist_ok=True)
                shutil.copy2(os.path.join(root, f), os.path.join(dst, rel))


def flatten_ladder(dst):
    """Rewrite defenses/ladder.py so every level folds into LADDER[0] (the new baseline)."""
    path = os.path.join(dst, "defenses", "ladder.py")
    if not os.path.exists(path):
        return []
    src = open(path).read()
    m = re.search(r"LADDER\s*=\s*\{(.*?)\n\}", src, re.S)
    if not m:
        return []
    body = m.group(1)
    entries = re.findall(r"^\s*(\d+)\s*:\s*\[(.*?)\]\s*,?\s*(?:#.*)?$", body, re.M)
    names = []
    for _, inner in sorted(entries, key=lambda e: int(e[0])):
        names += [x.strip() for x in inner.split(",") if x.strip() and not x.strip().startswith("#")]
    imports = "\n".join(line for line in src.split("\n") if line.startswith(("from ", "import ")))
    header = re.match(r'("""[\s\S]*?""")', src)
    doc = header.group(1) if header else '"""The ladder."""'
    doc = re.sub(r"\(YOUR FILE[^)]*\)", "(baseline inherited from the previous workshop)", doc)
    new = f'''{doc}

{imports}

# Every defense the previous workshop finished with runs as the always-on baseline.
# Your chapter's rounds go in levels 1..N below.
LADDER = {{
    0: [{", ".join(names)}],
}}
'''
    open(path, "w").write(new)
    return names


def build(src_lab, manifest, dst):
    os.makedirs(dst, exist_ok=True)
    copy_tree(src_lab, manifest, dst)
    shutil.copy2(os.path.join(ROOT, "scripts", "labnet.py"), os.path.join(dst, "labnet.py"))  # the guard, canonical
    if manifest.get("overlay_rounds"):
        overlay_solutions(src_lab, dst, manifest["overlay_rounds"])
        for pat in manifest["exclude"]:          # solutions may have re-added excluded files
            for root, dirs, files in os.walk(dst):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), dst)
                    if excluded(rel, manifest["exclude"]):
                        os.remove(os.path.join(root, f))
    baseline = flatten_ladder(dst) if manifest.get("flatten_ladder", True) else []
    open(os.path.join(dst, "tools", "checkpoint.py"), "w").write(CHECKPOINT_STUB)
    if manifest.get("readme") and os.path.exists(os.path.join(src_lab, manifest["readme"])):
        shutil.copy2(os.path.join(src_lab, manifest["readme"]), os.path.join(dst, "README.md"))
    sha = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    rel_src = os.path.relpath(src_lab, ROOT)
    json.dump({"contract_version": manifest.get("contract_version", "1.0"), "source": rel_src, "built_from": sha or None,
               "default_level": 0, "baseline_checks": baseline,
               "description": f"End state of {rel_src}: its final solutions installed and its ladder flattened into the baseline."},
              open(os.path.join(dst, "STARTER.json"), "w"), indent=2)


def diff_trees(a, b):
    out = []
    dc = filecmp.dircmp(a, b, ignore=[".venv", "instance", "__pycache__", "logs"])

    def walk(d, prefix=""):
        for f in d.left_only:
            out.append(f"only in built:  {prefix}{f}")
        for f in d.right_only:
            out.append(f"only in starter: {prefix}{f}")
        for f in d.diff_files:
            out.append(f"differs:        {prefix}{f}")
        for name, sub in d.subdirs.items():
            walk(sub, prefix + name + "/")
    walk(dc)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="src", required=True, help="capstone lab folder (has starter.manifest.json)")
    ap.add_argument("--check", action="store_true", help="diff against the existing starter(s); exit 1 on drift")
    args = ap.parse_args()
    src_lab = os.path.abspath(args.src)
    mpath = os.path.join(src_lab, "starter.manifest.json")
    if not os.path.exists(mpath):
        sys.exit(f"{mpath} not found")
    manifest = json.load(open(mpath))
    drift = 0
    with tempfile.TemporaryDirectory() as tmp:
        built = os.path.join(tmp, "built")
        build(src_lab, manifest, built)
        for target in manifest["targets"]:
            dst = os.path.join(ROOT, target)
            if args.check:
                if not os.path.isdir(dst):
                    print(f"{target}: missing")
                    drift += 1
                    continue
                d = [line for line in diff_trees(built, dst) if not line.endswith("STARTER.json")]
                print(f"{target}: {'in sync' if not d else str(len(d)) + ' differences'}")
                for line in d[:50]:
                    print("   " + line)
                drift += bool(d)
            else:
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(built, dst)
                print(f"wrote {target} from {os.path.relpath(src_lab, ROOT)}")
    sys.exit(1 if drift else 0)


if __name__ == "__main__":
    main()
