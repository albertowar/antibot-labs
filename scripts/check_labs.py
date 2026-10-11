#!/usr/bin/env python3
"""Repo-wide lab checks: the conventions AGENTS.md promises, enforced.

    python3 scripts/check_labs.py        # or: make check

Exit 1 on any failure. Each failure is one line: ``<lab>: rule<N>: <detail>``.

Rules
  1  every lab with network code has lab/labnet.py byte-identical to scripts/labnet.py
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
"""

from __future__ import annotations

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANON = os.path.join(ROOT, "scripts", "labnet.py")
LABS = sorted(glob.glob(os.path.join(ROOT, "workshops", "*", "chapters", "*", "lab")))

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

    # rule 9: checkpoint with --catch-up, and solutions differ from student files
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
                    if os.path.exists(dst) and read(src) == read(dst):
                        fail(lab, 9, f"{os.path.relpath(src, lab)} is byte-identical to {os.path.relpath(dst, lab)}")


def main() -> int:
    if not os.path.exists(CANON):
        print("scripts/labnet.py missing", file=sys.stderr)
        return 1
    for lab in LABS:
        check_lab(lab)
    for line in failures:
        print(line)
    print(f"{len(LABS)} labs checked, {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
