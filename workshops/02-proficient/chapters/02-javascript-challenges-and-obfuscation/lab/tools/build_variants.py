"""
Chapter 2 — Build the polymorphic challenge pool (Round 3)

Generates N challenge variants, each with its own random op chain and layout
probe size, then obfuscates them with javascript-obfuscator:

  demo_site/secrets/src/<id>.js        readable source (reference copy, never served)
  demo_site/static/variants/<id>.js    obfuscated, served to clients
  demo_site/secrets/manifest.json      id -> chain + probe (the server's answer key)

The manifest is the defender's secret. If it leaks, every variant can be
answered without running anything. The demo site never serves anything from
secrets/.

Rotation: re-run this while the demo site is running and restart it. Old
challenges in flight then fail and the browser simply re-solves. Real
deployments rotate on a timer (minutes to hours) and keep the previous pool
valid for one TTL, so in-flight challenges survive the switch.

Run (needs `npm ci` first):
    python tools/build_variants.py              # 12 variants
    python tools/build_variants.py --count 30 --seed 42
"""

import argparse
import json
import os
import random
import secrets
import shutil
import statistics
import subprocess
import sys
import time

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

from variants import probe_width, random_chain, random_probe, render

SECRETS_DIR = os.path.join(LAB_DIR, "demo_site", "secrets")
SRC_DIR = os.path.join(SECRETS_DIR, "src")
OUT_DIR = os.path.join(LAB_DIR, "demo_site", "static", "variants")
MANIFEST = os.path.join(SECRETS_DIR, "manifest.json")


def main():
    parser = argparse.ArgumentParser(description="Build the obfuscated challenge pool")
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--seed", type=int, default=None, help="reproducible pool (testing only)")
    args = parser.parse_args()

    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
    for d in (SRC_DIR, OUT_DIR):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    variants = []
    for _ in range(args.count):
        vid = f"{rng.getrandbits(48):012x}" if args.seed is not None else secrets.token_hex(6)
        chain, probe = random_chain(rng), random_probe(rng)
        with open(os.path.join(SRC_DIR, f"{vid}.js"), "w") as f:
            f.write(render(chain, probe))
        variants.append({"id": vid, "chain": chain, "probe": probe})

    try:
        out = subprocess.run(["node", os.path.join(LAB_DIR, "tools", "obfuscate.mjs"), SRC_DIR, OUT_DIR],
                             capture_output=True, text=True, check=True, cwd=LAB_DIR).stdout
    except FileNotFoundError:
        sys.exit("❌ node not found. Install Node 24 LTS, then run `npm ci` in lab/.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"❌ Obfuscation failed (did you run `npm ci`?):\n{e.stderr}")

    stats = {s["id"]: s for s in map(json.loads, out.splitlines())}
    for v in variants:
        v.update(bytes_plain=stats[v["id"]]["bytes_in"], bytes_obf=stats[v["id"]]["bytes_out"])

    with open(MANIFEST, "w") as f:
        json.dump({"built_at": time.time(), "variants": variants}, f, indent=1)

    plain = statistics.median(v["bytes_plain"] for v in variants)
    obf = statistics.median(v["bytes_obf"] for v in variants)
    ms = statistics.median(s["ms"] for s in stats.values())
    print(f"✅ Built {len(variants)} variants in demo_site/static/variants/")
    print(f"   size: {plain / 1024:.1f} KB readable -> {obf / 1024:.1f} KB obfuscated "
          f"(median, {obf / plain:.1f}x)")
    print(f"   obfuscation cost: median {ms:.0f} ms per variant (why we never do it per request)")
    print(f"   sample: {variants[0]['id']} chain={len(variants[0]['chain'])} ops, "
          f"probe offsetWidth={probe_width(variants[0]['probe'])}px")


if __name__ == "__main__":
    main()
