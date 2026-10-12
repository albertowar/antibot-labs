#!/usr/bin/env python3
"""
Which changed Python files changed in *code*, not just in docstrings and comments?

    python scripts/code_diff.py                 # working tree vs HEAD
    python scripts/code_diff.py --base main     # working tree vs main
    python scripts/code_diff.py --base main -v  # also print the code-level diff

Each changed .py file (renames followed) is parsed at the base ref and in the working tree,
docstrings are dropped (the AST already drops comments) and the two trees are compared.
A sweep that edits prose across many files (a renumber, a rename in docstrings) should report
only the files you meant to change in code; run those files' labs, not every lab.

Exit status: 0 if no file changed in code, 1 if some did (listed), 2 on a parse error.
"""

import argparse
import ast
import difflib
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def changed_py(base):
    """(old_path, new_path) pairs for .py files changed between base and the working tree."""
    out = git("diff", "-M", "--name-status", base, "--", "*.py")
    pairs = []
    for line in out.splitlines():
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R"):
            pairs.append((parts[1], parts[2]))
        elif status == "D":
            pairs.append((parts[1], None))
        elif status == "A":
            pairs.append((None, parts[1]))
        else:
            pairs.append((parts[1], parts[1]))
    for path in git("ls-files", "--others", "--exclude-standard", "--", "*.py").splitlines():
        pairs.append((None, path))
    return pairs


def strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


def code_of(source, label):
    try:
        return ast.unparse(strip_docstrings(ast.parse(source)))
    except SyntaxError as e:
        print(f"PARSE ERROR {label}: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--base", default="HEAD", help="git ref to compare against (default HEAD)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the code-level diff")
    args = ap.parse_args()

    pairs = changed_py(args.base)
    changed = []
    for old, new in pairs:
        before = code_of(git("show", f"{args.base}:{old}"), old) if old else ""
        after = code_of(open(os.path.join(ROOT, new), encoding="utf-8").read(), new) if new else ""
        if before != after:
            changed.append((old, new, before, after))
    # git cannot pair renames of byte-identical copies (solutions/roundN/...): an add and a delete
    # with the same code are a move, not a change.
    added = [c for c in changed if c[0] is None]
    for gone in [c for c in changed if c[1] is None]:
        twin = next((a for a in added if a[3] == gone[2]), None)
        if twin:
            added.remove(twin)
            changed.remove(twin)
            changed.remove(gone)
    print(f"{len(pairs)} changed .py file(s) vs {args.base}; {len(changed)} changed in code:")
    for old, new, before, after in changed:
        name = new if old in (None, new) else f"{old} -> {new}"
        print(f"  {name or old}")
        if args.verbose:
            for ln in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=1):
                if not ln.startswith(("---", "+++")):
                    print(f"      {ln}")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
