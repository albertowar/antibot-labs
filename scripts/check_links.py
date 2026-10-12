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

Exit status: 0 if every path resolves, 1 otherwise.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = ("workshops/", "scripts/", "onboarding/", "theme/", "pitch/")
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
REPO_PATH = re.compile(r"(?<![\w./-])((?:" + "|".join(re.escape(t) for t in TOP) + r")[\w./@+-]*)")
PLACEHOLDER = re.compile(r"[<>*{}]|\.\.\.|…|NN|<w>")
REL_SPAN = re.compile(r"`(\.\.?/[^`\s]+\.md)`")
# Paths the docs name on purpose before they exist (the starter chain, TODO.md §1.6). Drop an entry
# once the folder is built.
PLANNED = ("workshops/02-proficient/starter", "workshops/03-advanced/starter", "workshops/04-ai-era-bots/starter")


def md_files(prefixes):
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = [f for f in out if os.path.exists(os.path.join(ROOT, f)) and "node_modules/" not in f]
    if prefixes:
        files = [f for f in files if any(f.startswith(p.rstrip("*")) for p in prefixes)]
    return files


def exists(path):
    path = re.sub(r":\d+(?:[-,]\d+)*$", "", path).rstrip(".,;:)")
    return os.path.exists(path) or os.path.exists(path.rstrip("/"))


def main(argv):
    bad = []
    for rel in md_files(argv):
        here = os.path.dirname(os.path.join(ROOT, rel))
        for n, line in enumerate(open(os.path.join(ROOT, rel), encoding="utf-8"), 1):
            for target in MD_LINK.findall(line) + REL_SPAN.findall(line):
                if re.match(r"^[a-z]+:|^#|^/", target) or PLACEHOLDER.search(target):
                    continue
                if not exists(os.path.normpath(os.path.join(here, target.split("#")[0]))):
                    bad.append((rel, n, target))
            for target in REPO_PATH.findall(line):
                if PLACEHOLDER.search(target) or target.startswith(PLANNED):
                    continue
                if not exists(os.path.join(ROOT, target)):
                    bad.append((rel, n, target))
    for rel, n, target in bad:
        print(f"{rel}:{n}: missing {target}")
    print(f"{len(bad)} missing path(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
