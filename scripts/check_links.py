#!/usr/bin/env python3
"""
Check that repo paths named in Markdown actually exist.

    python scripts/check_links.py                  # every tracked/untracked .md file
    python scripts/check_links.py workshops/01-*   # only files under these paths

Checks two kinds of reference:
  - relative Markdown links, [text](path) and [text](path#anchor), and relative paths in code
    spans to a .md file (`../chapter_03_content.md`), resolved against the file;
  - repo paths written out in prose, commands or code spans, e.g. `workshops/01-initiation/...`,
    `scripts/x.py`, `onboarding/...` (resolved against the repo root; a trailing :line is ignored).
Paths with placeholders (<NN>, *, {..}, ...) are skipped. Run it after renaming or moving a
chapter, file or folder: it is the cheap way to catch the references a rename broke.

Two repos, one script. The series is split between the slides repo (docs, decks, theme,
onboarding, pitch, university) and the labs repo (labs, starters, the store contract, the lab
scripts), which keep the same ``workshops/<NN>/chapters/<slug>/`` paths. A path that does not
resolve here is tried against the sibling checkout named by ``ANTIBOT_SIBLING_ROOT`` (default:
``../antibot-labs`` when run from the slides repo, ``../antibot-workshop-slides`` from the labs
repo). When no sibling checkout exists, those paths are counted and skipped with one warning,
so CI without a sibling stays green. This file is byte-identical in both repos (like
``labnet.py``): edit it in one and copy it to the other.

Exit status: 0 if every path resolves (or could only be checked against a missing sibling),
1 otherwise.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
IS_SLIDES_REPO = os.path.isdir(os.path.join(ROOT, "theme"))
SIBLING = os.path.abspath(os.environ.get(
    "ANTIBOT_SIBLING_ROOT",
    os.path.join(ROOT, "..", "antibot-labs" if IS_SLIDES_REPO else "antibot-workshop-slides")))
SIBLING_OK = os.path.isdir(SIBLING)
TOP = ("workshops/", "scripts/", "onboarding/", "theme/", "pitch/", "university/")
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
REPO_PATH = re.compile(r"(?<![\w./-])((?:" + "|".join(re.escape(t) for t in TOP) + r")[\w./@+-]*)")
PLACEHOLDER = re.compile(r"[<>*{}]|\.\.\.|…|NN|<w>")
REL_SPAN = re.compile(r"`(\.\.?/[^`\s]+\.md)`")


def md_files(prefixes):
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = [f for f in out if os.path.exists(os.path.join(ROOT, f)) and "node_modules/" not in f]
    if prefixes:
        files = [f for f in files if any(f.startswith(p.rstrip("*")) for p in prefixes)]
    return files


def clean(path):
    return re.sub(r":\d+(?:[-,]\d+)*$", "", path).rstrip(".,;:)")


def exists_at(path):
    return os.path.exists(path) or os.path.exists(path.rstrip("/"))


def resolve(rel_to_root):
    """'ok' if the path exists in this repo or the sibling, 'sibling' if only a missing sibling
    could hold it, 'missing' otherwise. ``rel_to_root`` is the path relative to the repo root."""
    rel_to_root = clean(rel_to_root)
    if exists_at(os.path.join(ROOT, rel_to_root)):
        return "ok"
    if not SIBLING_OK:
        return "sibling"
    return "ok" if exists_at(os.path.join(SIBLING, rel_to_root)) else "missing"


def main(argv):
    bad, unchecked = [], 0
    for rel in md_files(argv):
        here = os.path.dirname(rel)
        for n, line in enumerate(open(os.path.join(ROOT, rel), encoding="utf-8"), 1):
            targets = []
            for target in MD_LINK.findall(line) + REL_SPAN.findall(line):
                if re.match(r"^[a-z]+:|^#|^/", target) or PLACEHOLDER.search(target):
                    continue
                targets.append((target, os.path.normpath(os.path.join(here, target.split("#")[0]))))
            for target in REPO_PATH.findall(line):
                if PLACEHOLDER.search(target):
                    continue
                targets.append((target, target))
            for target, rel_to_root in targets:
                if rel_to_root.startswith(".."):
                    bad.append((rel, n, target))
                    continue
                state = resolve(rel_to_root)
                if state == "missing":
                    bad.append((rel, n, target))
                elif state == "sibling":
                    unchecked += 1
    for rel, n, target in bad:
        print(f"{rel}:{n}: missing {target}")
    if unchecked:
        print(f"warning: {unchecked} path(s) not found here and no sibling checkout at {SIBLING} "
              f"to check them against (set ANTIBOT_SIBLING_ROOT)")
    print(f"{len(bad)} missing path(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
