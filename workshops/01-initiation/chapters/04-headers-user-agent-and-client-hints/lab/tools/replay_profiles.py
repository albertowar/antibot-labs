"""
Real browsers, replayed: the other half of every Chapter 4 measurement.

`tools/profiles/*.json` hold what real Chrome and Firefox sent to this store (the output of
/lab/headers/check). This replays them byte for byte (same names, values and ORDER) against the
store and reports any request that is stopped. The shoppers in tools/population.py are built from
`tools/browsers.py` templates; these are the ground truth those templates were made from.

    python tools/replay_profiles.py              # replay every profile, show verdicts and reasons
    python tools/replay_profiles.py --templates  # do browsers.py's templates agree with the profiles?

To add your own browser: open http://127.0.0.1:5000/ and then /lab/headers/check (with DEFENSE_LEVEL=4, so
Chromium has negotiated its hints) and save the page as tools/profiles/<name>.json. Or run
`python tools/capture_profiles.py` (needs a display).

Trade-off: a replay is only as good as its capture. Profiles go stale as browsers update, so
re-capture them whenever you bump `policy.MIN_CHROME_MAJOR`.
"""

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402

PROFILES_DIR = os.path.join(HERE, "profiles")
PATHS = ["/", "/products", "/api/products"]
HIGH_ENTROPY = ("sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-ch-ua-full-version-list", "sec-ch-ua-model")


def load_profiles():
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
        with open(path) as f:
            data = json.load(f)
        data.setdefault("name", os.path.splitext(os.path.basename(path))[0])
        profiles.append(data)
    return profiles


def replay_one(profile, path, index=0):
    """Send the profile's headers exactly as captured, from a home address, as a labelled human."""
    headers = [(n, v) for n, v in profile["headers_received"] if n.lower() != "host"]
    client = LabClient(f"human:profile:{profile['name']}", ip=world_pool("home_fiber")[index])
    return client.get(path, headers)


def run():
    """Replay every profile against every path. One result per request (the shape the checkpoint reads)."""
    results = []
    for i, profile in enumerate(load_profiles()):
        for path in PATHS:
            r = replay_one(profile, path, i)
            timing = r.headers.get("Server-Timing", "")
            gate_ms = float(timing.split("gate;dur=")[1].split(",")[0]) if "gate;dur=" in timing else None
            results.append({"profile": profile["name"], "path": path, "status": r.status_code,
                            "verdict": r.headers.get("X-Lab-Verdict"), "score": int(r.headers.get("X-Lab-Score", 0)),
                            "signals": r.headers.get("X-Lab-Signals", ""), "gate_ms": gate_ms})
    return results


def compare_templates():
    """Do browsers.py's templates agree with the captures on header names and their order? Returns problems."""
    problems = []
    for profile in load_profiles():
        ua = next((v for n, v in profile["headers_received"] if n.lower() == "user-agent"), "")
        if "Chrome/" in ua:
            major = int(ua.split("Chrome/")[1].split(".")[0])
            platform = "linux" if "Linux" in ua else "windows" if "Windows" in ua else "macos"
            template = browsers.headers_for(("chrome", major, platform), "typed", BASE_URL)
        elif "Firefox/" in ua:
            template = browsers.headers_for(("firefox", int(ua.split("Firefox/")[1].split(".")[0])), "typed", BASE_URL)
        else:
            continue
        # A profile has the Host header, a Cookie and (Chromium, after Accept-CH) the high-entropy hints; a template does not.
        captured = [n.lower() for n, _ in profile["headers_received"] if n.lower() not in ("host", "cookie") + HIGH_ENTROPY]
        wanted = [n.lower() for n, _ in template]
        if captured != wanted:
            problems.append(f"{profile['name']}: browsers.py order differs\n    capture : {captured}\n    template: {wanted}")
    return problems


def print_run(results):
    print("=== Real browsers (replayed profiles) ===")
    for r in results:
        mark = "ok  " if r["status"] == 200 and r["score"] == 0 else "FAIL" if r["status"] != 200 else "warn"
        print(f"  {mark} {r['profile']:<22} GET {r['path']:<14} {r['status']}  score={r['score']} {r['signals']}")
    blocked = sum(r["status"] != 200 for r in results)
    print(f"\n  Stopped: {blocked}/{len(results)} requests across {len({r['profile'] for r in results})} profiles")


if __name__ == "__main__":
    if "--templates" in sys.argv:
        problems = compare_templates()
        print("tools/browsers.py agrees with the captured profiles (header names and order)." if not problems else "\n".join(problems))
        sys.exit(1 if problems else 0)
    out = run()
    if not out:
        print(f"No profiles found in {PROFILES_DIR}")
        sys.exit(1)
    print_run(out)
    sys.exit(1 if any(r["status"] != 200 for r in out) else 0)
