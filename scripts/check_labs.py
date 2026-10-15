#!/usr/bin/env python3
"""Repo-wide lab checks: the conventions AGENTS.md promises, enforced.

    python3 scripts/check_labs.py               # every starter and lab; or: make check
    python3 scripts/check_labs.py <lab folder>  # one

Exit 1 on any failure. Each failure is one line: ``<lab>: rule<N>: <detail>``.

A lab is on the starter chain when it has ``tools/checkpoint_core.py`` (copied from
``workshops/<NN>/starter/``); rules 10-15 apply only there.

Rules
  1  every lab (and starter) with network code has labnet.py byte-identical to scripts/labnet.py
  2  every attacks/ or tools/ script that uses DEMO_URL or an HTTP client imports labnet
     (directly, or through a sibling module of the same lab that does)
  3  os.environ[...]("DEMO_URL") is read only inside labnet.py
  4  every Flask app.run(...) under lab/ binds host="127.0.0.1"
  5  every docker-compose ports: entry is bound to 127.0.0.1
  6  no HTTP-client call to a literal real-domain URL under attacks/, tools/, defenses/
     except the allowlisted opt-in tools below
  7  every lab has a README.md with a "## Rules of engagement" heading
  8  solutions live only at lab/solutions/roundN/
  9  every lab with solutions/ has tools/checkpoint.py offering --catch-up, and no solution
     file is byte-identical to the student file it replaces

Starter chain only (starters and the labs copied from them)
 10  every attacks/*.py imports labnet (directly or via a tools/ or attacks/ helper)
 11  no defenses/ or demo_site/ext/ file reads the ground-truth actor label
 12  pins in requirements.txt match the baseline where the package is used
 13  README.md starts with a "Starts from:" line naming the starter (labs only)
 14  solutions/roundN/ folders agree with ROUNDS in tools/checkpoint.py (labs only)
 15  no retired route names in demo_site/ (see AGENTS.md "Retired names")
"""

from __future__ import annotations

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANON = os.path.join(ROOT, "scripts", "labnet.py")
LABS = sorted(glob.glob(os.path.join(ROOT, "workshops", "*", "chapters", "*", "lab")))
STARTERS = sorted(glob.glob(os.path.join(ROOT, "workshops", "*", "starter")))
BASELINE = {"Flask": "3.1.3", "Flask-SQLAlchemy": "3.1.1", "SQLAlchemy": "2.1.4", "redis": "8.1.0", "fakeredis": "2.39.0",
            "fakeredis[lua]": "2.39.0", "requests": "2.34.2", "httpx": "0.28.1", "psycopg[binary]": "3.3.6"}
# /catalog is NOT retired: it is the starter's canonical alias of /products (contract §3.1).
RETIRED = [r'"/admin/', r"'/admin/", r'"/api/v0', r'"/api/sensor"', r'"/api/session"', r'"/api/fp"', r'"/telemetry"',
           r'"/products/<', r'"/signup"']

HTTP_CLIENTS = ("requests", "httpx", "urllib.request", "http.client", "playwright", "patchright",
                "camoufox", "selenium", "curl_cffi", "impit", "websockets", "aiohttp")
CLIENT_IMPORT = re.compile(r"^\s*(?:import|from)\s+(" + "|".join(re.escape(c) for c in HTTP_CLIENTS) + r")\b", re.M)
DEMO_URL_READ = re.compile(r"""environ(?:\.get\(\s*["']DEMO_URL["']|\[\s*["']DEMO_URL["']\](?!\s*=))""")
SIBLING_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
APP_RUN = re.compile(r"\.run\((?P<args>[^)]*)\)")
REAL_URL_CALL = re.compile(
    r"""(?:\.(?:get|post|put|delete|head|request|goto|urlopen|Client|Session|connect)\s*\(|urlopen\s*\()"""
    r"""[^\n]*?["']https?://(?!localhost|127\.|\[::1\]|[^/"']*\.(?:test|example|invalid|localhost)\b)[^"']*["']""")

# Opt-in tools that may reach the real internet, each off by default and documented in
# its lab README's "Rules of engagement".
OUTBOUND_ALLOWLIST = {
    "02-proficient/chapters/05-tls-and-network-fingerprinting/lab/tools/get_fingerproxy.py":
        "setup-time download of the pinned fingerproxy release, SHA-256 checked",
    "03-advanced/chapters/06-specialized-attack-scenarios/lab/defenses/breachcorpus.py":
        "k-anonymity range lookup against Pwned Passwords, only with HIBP_LIVE=1",
    "04-ai-era-bots/chapters/02-verified-bot-identity/lab/tools/verify_real.py":
        "bonus: resolve an IP from your own logs and download an operator's published range file",
}

failures: list[str] = []


def fail(lab: str, rule: int, detail: str) -> None:
    failures.append(f"{rel(lab)}: rule{rule}: {detail}")


def rel(path: str) -> str:
    return os.path.relpath(path, os.path.join(ROOT, "workshops"))


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def py_files(*dirs: str) -> list[str]:
    out = []
    for d in dirs:
        for dirpath, dirnames, files in os.walk(d):
            dirnames[:] = [x for x in dirnames if x not in ("__pycache__", "node_modules", ".venv")]
            out += [os.path.join(dirpath, f) for f in files if f.endswith(".py")]
    return sorted(out)


def uses_network(src: str) -> bool:
    return bool(DEMO_URL_READ.search(src) or "DEMO_URL" in src or CLIENT_IMPORT.search(src))


def check_lab(lab: str) -> None:
    attacks = os.path.join(lab, "attacks")
    tools = os.path.join(lab, "tools")
    scripts = py_files(*(d for d in (attacks, tools) if os.path.isdir(d)))
    srcs = {p: read(p) for p in scripts}
    network_scripts = [p for p, s in srcs.items() if uses_network(s) and os.path.basename(p) != "labnet.py"]
    has_network = bool(network_scripts)

    # rule 1: vendored copy identical
    vendored = os.path.join(lab, "labnet.py")
    if has_network:
        if not os.path.exists(vendored):
            fail(lab, 1, "lab/labnet.py missing")
        elif read(vendored) != read(CANON):
            fail(lab, 1, "lab/labnet.py differs from scripts/labnet.py")

    # rule 2: every network script imports labnet, directly or via a sibling that does
    by_module = {}
    root_helpers = {p: read(p) for p in glob.glob(os.path.join(lab, "*.py")) if os.path.basename(p) != "labnet.py"}
    for p, s in list(srcs.items()) + list(root_helpers.items()):
        by_module.setdefault(os.path.splitext(os.path.basename(p))[0], []).append(s)

    def imports_labnet(src: str, depth: int = 0) -> bool:
        if re.search(r"^\s*(?:from\s+labnet\s+import|import\s+labnet)\b", src, re.M):
            return True
        if depth > 2:
            return False
        for m in SIBLING_IMPORT.finditer(src):
            name = (m.group(1) or m.group(2)).split(".")[-1]
            for sib in by_module.get(name, []):
                if sib is not src and imports_labnet(sib, depth + 1):
                    return True
        return False

    for p in network_scripts:
        if rel(p) in OUTBOUND_ALLOWLIST:
            continue
        if not imports_labnet(srcs[p]):
            fail(lab, 2, f"{os.path.relpath(p, lab)} uses the network without importing labnet")

    # rule 3: DEMO_URL read only in labnet.py
    for p in py_files(lab):
        if os.path.basename(p) == "labnet.py":
            continue
        if DEMO_URL_READ.search(read(p)):
            fail(lab, 3, f"{os.path.relpath(p, lab)} reads DEMO_URL directly (use labnet.target)")

    # rule 4: Flask binds loopback
    for p in py_files(lab):
        src = read(p)
        if "Flask(" not in src and "flask" not in src.lower():
            continue
        for m in APP_RUN.finditer(src):
            args = m.group("args")
            if "port" not in args:
                continue
            if 'host="127.0.0.1"' not in args and "host='127.0.0.1'" not in args:
                fail(lab, 4, f"{os.path.relpath(p, lab)}: app.run(...) without host=\"127.0.0.1\"")

    # rule 5: compose ports bound to loopback
    for yml in glob.glob(os.path.join(lab, "*compose*.y*ml")):
        for i, line in enumerate(read(yml).splitlines(), 1):
            if not re.search(r"^\s*-\s*[\"']?\S+:\d+[\"']?\s*$|ports:", line):
                continue
            for port in re.findall(r"""["'](\d[\d.]*:\d+:\d+|\d+:\d+)["']""", line):
                if not port.startswith("127.0.0.1:"):
                    fail(lab, 5, f"{os.path.basename(yml)}:{i} port {port} not bound to 127.0.0.1")

    # rule 6: no literal real-domain client calls
    for p in py_files(*(d for d in (attacks, tools, os.path.join(lab, "defenses")) if os.path.isdir(d))):
        key = rel(p)
        if key in OUTBOUND_ALLOWLIST:
            continue
        for i, line in enumerate(read(p).splitlines(), 1):
            if REAL_URL_CALL.search(line):
                fail(lab, 6, f"{os.path.relpath(p, lab)}:{i} HTTP call to a non-local URL")

    if is_starter(lab):
        check_starter_chain(lab)
        return

    # rule 7: README with RoE
    readme = os.path.join(lab, "README.md")
    if not os.path.exists(readme):
        fail(lab, 7, "lab/README.md missing")
    elif not re.search(r"^## Rules of engagement\s*$", read(readme), re.M):
        fail(lab, 7, 'README.md has no "## Rules of engagement" heading')

    # rule 8: solutions layout
    for stray in ("defenses/solutions", "defenses/_solutions", "tools/solutions", "attacks/solutions"):
        if os.path.isdir(os.path.join(lab, stray)):
            fail(lab, 8, f"{stray}/ exists; solutions belong in lab/solutions/roundN/")
    solutions = os.path.join(lab, "solutions")
    if os.path.isdir(solutions):
        for entry in sorted(os.listdir(solutions)):
            if entry in ("README.md", "walkthrough.md", "answer_key.json", ".gitignore", "__pycache__"):
                continue
            if not re.fullmatch(r"round\d+", entry) and not os.path.isfile(os.path.join(solutions, entry)):
                fail(lab, 8, f"solutions/{entry}/ is not a roundN/ directory")

    # rule 9: checkpoint with --catch-up, and solutions differ from student files. A
    # starter-chain lab in the pre-written style (AGENTS.md "Demo store") ships complete
    # defenses, so its per-round solutions may equal the student files.
    pre_written = on_starter_chain(lab) and os.path.exists(readme) and "pre-written" in read(readme)
    if os.path.isdir(solutions):
        ckpt = os.path.join(tools, "checkpoint.py")
        if not os.path.exists(ckpt):
            fail(lab, 9, "solutions/ present but tools/checkpoint.py missing")
        elif "--catch-up" not in read(ckpt):
            fail(lab, 9, "tools/checkpoint.py has no --catch-up flag")
        for rnd in sorted(glob.glob(os.path.join(solutions, "round*"))):
            for dirpath, dirnames, files in os.walk(rnd):
                dirnames[:] = [x for x in dirnames if x != "__pycache__"]
                for f in files:
                    if f == "README.md" or f.endswith((".pyc", ".bak")):
                        continue
                    src = os.path.join(dirpath, f)
                    dst = os.path.join(lab, os.path.relpath(src, rnd))
                    if not pre_written and os.path.exists(dst) and read(src) == read(dst):
                        fail(lab, 9, f"{os.path.relpath(src, lab)} is byte-identical to {os.path.relpath(dst, lab)}")

    if on_starter_chain(lab):
        check_starter_chain(lab)


def is_starter(lab: str) -> bool:
    return os.path.basename(lab) == "starter"


def on_starter_chain(lab: str) -> bool:
    return os.path.exists(os.path.join(lab, "tools", "checkpoint_core.py"))


def check_starter_chain(lab: str) -> None:
    # rule 10: every attack imports labnet, directly or through a helper in tools/ or attacks/
    # (tools/labclient.py imports it, so `from labclient import ...` counts)
    def uses_labnet(src: str, seen: tuple = ()) -> bool:
        if re.search(r"^\s*(from\s+labnet\s+import|import\s+labnet)", src, re.M):
            return True
        for mod in re.findall(r"^\s*(?:from\s+(\w+)\s+import|import\s+(\w+))", src, re.M):
            name = mod[0] or mod[1]
            if name in seen:
                continue
            for d in ("tools", "attacks"):
                helper = os.path.join(lab, d, name + ".py")
                if os.path.exists(helper) and uses_labnet(read(helper), seen + (name,)):
                    return True
        return False

    for f in sorted(glob.glob(os.path.join(lab, "attacks", "*.py"))):
        if os.path.basename(f).startswith("_") and os.path.basename(f) != "__main__.py":
            continue
        if not uses_labnet(read(f)):
            fail(lab, 10, f"attacks/{os.path.basename(f)} does not import labnet (directly or via tools/labclient.py)")

    # rule 11: no defense reads the ground-truth actor label
    for p in py_files(*(os.path.join(lab, d) for d in ("defenses", os.path.join("demo_site", "ext")))):
        src = read(p)
        if 'lab.actor"' in src or 'X-Lab-Actor"' in src or "HTTP_X_LAB_ACTOR" in src:
            fail(lab, 11, f"{os.path.relpath(p, lab)} reads the ground-truth actor")

    # rule 12: baseline pins
    req = os.path.join(lab, "requirements.txt")
    if os.path.exists(req):
        for line in read(req).splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\[\]-]+)==([\w.]+)", line)
            if m and m.group(1) in BASELINE and m.group(2) != BASELINE[m.group(1)]:
                fail(lab, 12, f"requirements.txt: {m.group(1)}=={m.group(2)} (baseline {BASELINE[m.group(1)]})")

    # rule 15: no retired routes (/api/telemetry and /api/products/<sku> are canonical under url_prefix="/api")
    for p in py_files(os.path.join(lab, "demo_site")):
        src = read(p)
        under_api = 'url_prefix="/api"' in src
        for pat in RETIRED:
            if pat in src and not (under_api and pat in ('"/telemetry"', '"/products/<')):
                fail(lab, 15, f"{os.path.relpath(p, lab)}: retired route {pat}")

    if is_starter(lab):
        return

    # rule 13: "Starts from:" line
    readme = os.path.join(lab, "README.md")
    head = read(readme)[:600] if os.path.exists(readme) else ""
    if "Starts from:" not in head:
        fail(lab, 13, "README.md has no 'Starts from:' line in the first lines")

    # rule 14: ROUNDS in tools/checkpoint.py vs solutions/round<N>/
    cp = os.path.join(lab, "tools", "checkpoint.py")
    if os.path.exists(cp):
        rounds = set(int(n) for n in re.findall(r"^\s*(\d+)\s*:\s*Round\(", read(cp), re.M))
        have = set(int(os.path.basename(d)[5:]) for d in glob.glob(os.path.join(lab, "solutions", "round*"))
                   if os.path.basename(d)[5:].isdigit())
        missing = sorted(r for r in rounds if r > 0 and r not in have)
        if missing:
            fail(lab, 14, f"ROUNDS {missing} have no solutions/round<N>/")
    else:
        fail(lab, 14, "no tools/checkpoint.py")


def main() -> int:
    if not os.path.exists(CANON):
        print("scripts/labnet.py missing", file=sys.stderr)
        return 1
    targets = [os.path.abspath(a) for a in sys.argv[1:]] or STARTERS + LABS
    for lab in targets:
        check_lab(lab)
    for line in failures:
        print(line)
    print(f"{len(targets)} labs checked, {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
