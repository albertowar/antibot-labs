#!/usr/bin/env python3
"""
Do the labs still match the dependency baseline, and is it still fresh?

    python scripts/audit_deps.py          # or: make audit-deps

Three report-only passes over every workshops/**/requirements*.txt:

1. Every exact pin is diffed against the baseline table in AGENTS.md ("Dependency baseline").
   A pin may deviate only when its line carries a comment naming the constraint (the AGENTS rule);
   an uncommented deviation is a failure.
2. Every file's "Pins verified <Month YYYY>" header is parsed; a missing header, or one older
   than STALE_MONTHS, is a warning - the signal to rerun the refresh procedure in AGENTS.md.
3. If pip-audit is on PATH, the deduped pin set is written to a temp file and audited once
   (advisories are warnings; upgrading is the manual AGENTS.md procedure, not this script).

Exit status: 1 on uncommented baseline deviations, 0 otherwise (staleness and advisories warn).
"""

import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
AGENTS = os.path.join(ROOT, "AGENTS.md")
STALE_MONTHS = 3
MONTHS = {m: i + 1 for i, m in enumerate(
    ["January", "February", "March", "April", "May", "June",
     "July", "August", "September", "October", "November", "December"])}


def norm(name):
    """Pip-style package name, extras stripped: Flask-Session == flask-session, fakeredis[lua] == fakeredis."""
    return re.sub(r"\[.*\]", "", name).strip().lower().replace("_", "-")


def baseline():
    """{package: version} from the AGENTS.md table (only cells that are exact versions)."""
    pins = {}
    in_table = False
    for line in open(AGENTS, encoding="utf-8"):
        if line.startswith("## "):
            in_table = line.startswith("## Dependency baseline")
        if not in_table or not line.startswith("|") or "---" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or cells[0] in ("Component", ""):
            continue
        names = [n.strip() for n in cells[0].split("/")]
        versions = [v.strip() for v in cells[1].split("/")]
        if len(names) != len(versions):
            continue
        for n, v in zip(names, versions):
            # only pip packages with exact versions; image rows (backticks, spaces) and the
            # Python/Node floors ("3.12+", "24 LTS") fail these patterns and drop out
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9._\[\]-]*", n) and re.fullmatch(r"\d+(\.\d+)+", v):
                pins[norm(n)] = v
    return pins


def requirement_files():
    out = []
    for dirpath, dirnames, files in os.walk(os.path.join(ROOT, "workshops")):
        dirnames[:] = [d for d in dirnames if d not in (".venv", "node_modules", "__pycache__", "instance")]
        out += [os.path.join(dirpath, f) for f in files if re.fullmatch(r"requirements[\w.-]*\.txt", f)]
    return sorted(out)


def parse_pins(path):
    """(name, version) per exact pin, the header's (month, year) or None, and the file's comment text.

    The AGENTS rule lets a pin deviate "with a comment naming the constraint"; in practice that
    comment sits on or above the pin, so a deviation counts as commented when any comment line in
    the file names the package.
    """
    pins, verified, comments = [], None, []
    for i, line in enumerate(open(path, encoding="utf-8")):
        if i == 0:
            m = re.search(r"Pins verified (\w+) (\d{4})", line)
            if m and m.group(1) in MONTHS:
                verified = (MONTHS[m.group(1)], int(m.group(2)))
        if "#" in line:
            comments.append(line.split("#", 1)[1].lower())
        code = line.split("#", 1)[0].strip()
        m = re.match(r"([A-Za-z][A-Za-z0-9._\[\]-]*)==([\w.]+)$", code)
        if m:
            pins.append((m.group(1), m.group(2)))
    return pins, verified, " ".join(comments)


def main():
    base = baseline()
    failures, warnings, all_pins = [], [], {}
    today = datetime.date.today()
    for path in requirement_files():
        rel = os.path.relpath(path, ROOT)
        pins, verified, comments = parse_pins(path)
        # the AGENTS header rule covers the main requirements.txt; the side files only get pin checks
        if os.path.basename(path) == "requirements.txt":
            if verified is None:
                warnings.append(f"{rel}: no 'Pins verified <Month YYYY>' header")
            elif (today.year - verified[1]) * 12 + (today.month - verified[0]) > STALE_MONTHS:
                warnings.append(f"{rel}: pins verified {verified[0]}/{verified[1]}, over {STALE_MONTHS} months ago")
        for name, version in pins:
            all_pins.setdefault(f"{name}=={version}", rel)
            want = base.get(norm(name))
            if want and version != want:
                if norm(name) in comments:
                    warnings.append(f"{rel}: {name}=={version} deviates from baseline {want} (commented, allowed)")
                else:
                    failures.append(f"{rel}: {name}=={version} deviates from baseline {want}")
    print(f"{len(requirement_files())} requirements files, {len(base)} baseline pins, {len(all_pins)} unique pins")
    for msg in failures:
        print(f"FAIL {msg}")
    for msg in warnings:
        print(f"warn {msg}")
    if shutil.which("pip-audit"):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(sorted(all_pins)))
            tmp = fh.name
        print("\n== pip-audit over the deduped pin set (advisories are warnings)")
        r = subprocess.run(["pip-audit", "--no-deps", "-r", tmp], capture_output=True, text=True)
        print((r.stdout + r.stderr).strip())
        os.unlink(tmp)
    else:
        print("\npip-audit not on PATH; skipped the advisory scan (pipx install pip-audit)")
    print(f"\naudit: {'FAIL' if failures else 'OK'} ({len(failures)} deviation(s), {len(warnings)} warning(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
