"""
W2 fingerprint coherence (W2 Ch2, Ch9) — carried into W4 Ch4 as a SHADOW instrument

Stealth browsers have removed the obvious tells (webdriver, $cdc_), so we
stop asking "is this automation?" and start asking whether the parts of the
fingerprint describe one real device:

    Software WebGL renderer (SwiftShader, llvmpipe, Basic Render)   SOFTWARE_RENDERER_POINTS
    Desktop browser with no window chrome (outer == inner)           +30
    JS userAgent differs from the HTTP User-Agent header             +50
    OS in the UA vs. navigator.platform vs. UA-CH platform disagree  +40
    A Web Worker sees a different navigator than the page            +50

Why these work: headless Chromium on a server has no GPU, so it renders WebGL
in software, and it has no window frame. JavaScript-level spoofing (stealth
plugins, init scripts) patches the page's navigator but rarely the Worker's.

Where they fail:
  - Real people use software rendering: VDI/Citrix sessions without GPU
    passthrough, VMs, some locked-down corporate laptops, very old GPUs on
    driver blocklists.
  - Firefox with resistFingerprinting reports a screen that matches the
    window, so it has no window chrome either.
  - Native spoofing (Camoufox patches Firefox in C++) keeps the page, the
    Worker and the headers consistent, and supplies a realistic GPU string.
"""

import hashlib
import json
import re

# W2 Ch9 Round 1 settled this: a software renderer alone only challenges
# (real VDI users have one); with one more headless tell it still blocks.
SOFTWARE_RENDERER_POINTS = 30

SOFTWARE_RENDERER = re.compile(r"SwiftShader|llvmpipe|softpipe|Basic Render|Software Rasterizer|"
                               r"Mesa OffScreen", re.I)
MOBILE_UA = re.compile(r"Mobile|Android|iPhone|iPad", re.I)


def os_from_ua(ua):
    if re.search(r"iPhone|iPad|iPod", ua):
        return "ios"
    if "Android" in ua:
        return "android"
    if "Windows" in ua:
        return "windows"
    if "Macintosh" in ua or "Mac OS X" in ua:
        return "mac"
    if "CrOS" in ua:
        return "chromeos"
    if "Linux" in ua or "X11" in ua:
        return "linux"
    return "unknown"


def os_from_platform(platform):
    p = (platform or "").lower()
    if p.startswith("win"):
        return "windows"
    if p.startswith("mac"):
        return "mac"
    if p in ("iphone", "ipad", "ipod") or p.startswith("ios"):
        return "ios"
    if "android" in p:
        return "android"
    if "linux" in p:
        return "linux"  # Android also reports "Linux armv8l"; checked below
    if "chrome os" in p or "cros" in p:
        return "chromeos"
    return "unknown"


def fingerprint_hash(fp):
    """A stable id for 'this browser on this machine', used by L4 to cluster logins."""
    stable = {k: fp.get(k) for k in ("ua", "platform", "hc", "mem", "screen", "tz", "languages", "canvas")}
    stable["renderer"] = (fp.get("webgl") or {}).get("renderer")
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:16]


def score_coherence(fp, http_ua=None):
    if not fp:
        return 0, []  # missing telemetry is an L0 signal
    points, reasons = 0, []
    ua = fp.get("ua") or ""
    mobile = bool(MOBILE_UA.search(ua))

    renderer = (fp.get("webgl") or {}).get("renderer") or ""
    if SOFTWARE_RENDERER.search(renderer):
        points += SOFTWARE_RENDERER_POINTS
        reasons.append(f"Software WebGL renderer: {renderer[:60]}")

    win = fp.get("win") or []
    if not mobile and len(win) == 4:
        outer_w, outer_h, inner_w, inner_h = win
        if outer_h == 0 or (outer_w == inner_w and outer_h == inner_h):
            points += 30
            reasons.append(f"No window chrome: outer {outer_w}x{outer_h} == inner {inner_w}x{inner_h}")

    if http_ua and ua and http_ua != ua:
        points += 50
        reasons.append("navigator.userAgent differs from the User-Agent header")

    ua_os = os_from_ua(ua)
    plat_os = os_from_platform(fp.get("platform"))
    if ua_os == "android" and plat_os == "linux":
        plat_os = "android"
    if ua_os == "ios" and plat_os == "mac":
        plat_os = "ios"  # iPadOS in desktop mode reports MacIntel
    uach_os = os_from_platform((fp.get("uach") or {}).get("platform")) if fp.get("uach") else None
    if uach_os == "unknown":
        uach_os = None
    seen = {o for o in (ua_os, plat_os, uach_os) if o and o != "unknown"}
    if len(seen) > 1:
        points += 40
        reasons.append(f"OS disagrees: UA={ua_os}, navigator.platform={plat_os}, UA-CH={uach_os}")

    worker = fp.get("worker")
    if worker:
        diffs = [k for k, fk in (("ua", "ua"), ("platform", "platform"), ("hc", "hc"))
                 if worker.get(k) is not None and worker.get(k) != fp.get(fk)]
        if diffs:
            points += 50
            reasons.append(f"Web Worker navigator differs from the page: {', '.join(diffs)}")
    return points, reasons


if __name__ == '__main__':
    headless = {"ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "platform": "Linux x86_64", "hc": 8, "win": [1280, 720, 1280, 720],
                "webgl": {"renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"},
                "worker": {"ua": "x", "platform": "Linux x86_64", "hc": 8}}
    print(score_coherence(headless))
