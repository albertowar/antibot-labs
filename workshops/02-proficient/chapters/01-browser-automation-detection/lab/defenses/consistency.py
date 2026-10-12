"""
W2 Ch1 — Defense Layer 2: Consistency (Section 1.2)

Once navigator.webdriver is gone, ask a harder question: does this browser
tell the same story everywhere we can look? A real Chrome never contradicts
itself. A bot that changed one value (the User-Agent, over CDP) without
changing everything that depends on it does.

  JS vs HTTP     navigator.userAgent vs the User-Agent header;
                 navigator.userAgentData brands/platform vs Sec-CH-UA.
                 This is the check Workshop 1, Chapter 4 handed over.
  Headless shape A desktop browser window has toolbars, so outerHeight is
                 larger than innerHeight. Headless windows have no UI.
  Self-contradiction
                 Headless shell reports Notification.permission "denied"
                 while the Permissions API says "prompt" for the same thing.
  Chromium features
                 Desktop Chromium always has window.chrome and the five
                 built-in PDF viewer plugins. Headless shell has neither.
  Software GPU   SwiftShader/llvmpipe renderers: typical of headless and
                 of servers, but also of VDI, VMs and old hardware, so it is
                 deliberately weak.

False positives to expect (and why the weights are what they are):
  - Fullscreen / kiosk mode removes the browser UI (headless shape alone
    only reaches "suspicious").
  - Enterprise policy can disable the PDF viewer (0 plugins).
  - UA-switcher extensions often change the header but not navigator, or
    vice versa (JS vs HTTP mismatch).
  - VDI and remote-desktop users render with software GPUs.

Enabled when DEFENSE_LEVEL >= 2.
"""

import re

# Sec-CH-UA is a Structured Header list: "Brand";v="version", ...
BRAND_RE = re.compile(r'"([^"]*)"\s*;\s*v\s*=\s*"([^"]*)"')
SOFTWARE_RENDERER_RE = re.compile(r"swiftshader|llvmpipe|softpipe|software rasterizer", re.I)

# navigator.platform values a real browser reports for each UA operating system
PLATFORM_PREFIXES = {
    "Windows": ("Win32",),
    "macOS": ("MacIntel",),
    "Linux": ("Linux",),
    "Android": ("Linux", "Android"),
    "iOS": ("iPhone", "iPad", "MacIntel"),
}


def ua_os(ua):
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Windows" in ua:
        return "Windows"
    if "Macintosh" in ua:
        return "macOS"
    if "Linux" in ua or "X11" in ua:
        return "Linux"
    return None


def is_desktop_chromium(signals):
    ua = signals.get("ua") or ""
    uad = signals.get("uad")
    return ("Chrome/" in ua and "Mobile" not in ua and "Android" not in ua
            and uad is not None and not uad.get("mobile"))


def is_desktop(signals):
    ua = signals.get("ua") or ""
    return not any(token in ua for token in ("Mobile", "Android", "iPhone", "iPad"))


def check_js_vs_http(signals, headers):
    """The JS environment and the HTTP headers must describe the same browser."""
    score = 0
    reasons = []
    header_ua = headers.get("User-Agent", "")
    js_ua = signals.get("ua") or ""
    if js_ua and header_ua and js_ua != header_ua:
        score += 40
        reasons.append("User-Agent header and navigator.userAgent disagree")

    uad = signals.get("uad")
    http_brands = BRAND_RE.findall(headers.get("Sec-CH-UA", ""))
    if uad:
        js_brands = set(uad.get("brands") or [])
        if any(b.startswith("HeadlessChrome/") for b in js_brands):
            score += 40
            reasons.append("navigator.userAgentData brands include HeadlessChrome")
        if http_brands and js_brands != {f"{b}/{v}" for b, v in http_brands}:
            score += 40
            reasons.append("navigator.userAgentData brands differ from the Sec-CH-UA header")
        http_platform = headers.get("Sec-CH-UA-Platform", "").strip('"')
        if http_platform and uad.get("platform") and uad["platform"] != http_platform:
            score += 30
            reasons.append(f"userAgentData.platform is {uad['platform']} but Sec-CH-UA-Platform is {http_platform}")

    os_name = ua_os(js_ua)
    platform = signals.get("platform") or ""
    if os_name and platform and not platform.startswith(PLATFORM_PREFIXES[os_name]):
        score += 20
        reasons.append(f"navigator.platform '{platform}' does not match a {os_name} User-Agent")
    return score, reasons


def check_headless_shape(signals):
    """
    Round 2: a desktop browser window has browser UI around the page, so the
    outer window is larger than the viewport. Headless windows have none.
    """
    if not is_desktop(signals):
        return 0, []
    g = signals.get("geometry") or {}
    # TODO (Round 2): using g["outer_w"], g["outer_h"], g["inner_w"], g["inner_h"]:
    #   - outer width or height of 0             -> (30, [reason])
    #   - outer size exactly equals the viewport -> (20, [reason])
    #   - otherwise                              -> (0, [])
    # Why only 20? Think about who browses in fullscreen or kiosk mode.
    return 0, []


def check_permission_contradiction(signals):
    """Two APIs reporting the same permission must agree."""
    if signals.get("notification_permission") == "denied" and signals.get("permission_query") == "prompt":
        return 30, ["Notification.permission is 'denied' but permissions.query says 'prompt'"]
    return 0, []


def check_chromium_features(signals):
    """Things every desktop Chromium has that headless shell does not."""
    if not is_desktop_chromium(signals):
        return 0, []
    score = 0
    reasons = []
    if signals.get("plugins") == 0:
        score += 15
        reasons.append("Desktop Chromium with 0 plugins (built-in PDF viewer missing)")
    if not signals.get("has_chrome_object"):
        score += 15
        reasons.append("Chromium User-Agent but no window.chrome object")
    return score, reasons


def check_software_renderer(signals):
    """Weak on purpose: VDI, VMs and remote desktops look like this too."""
    renderer = (signals.get("webgl") or {}).get("renderer") or ""
    if SOFTWARE_RENDERER_RE.search(renderer):
        return 10, [f"Software WebGL renderer ({renderer[:60]})"]
    return 0, []


def score_consistency(signals, headers):
    """Layer 2. `headers` is the request's header mapping. Returns (score, reasons)."""
    score = 0
    reasons = []
    for check in (lambda: check_js_vs_http(signals, headers),
                  lambda: check_headless_shape(signals),
                  lambda: check_permission_contradiction(signals),
                  lambda: check_chromium_features(signals),
                  lambda: check_software_renderer(signals)):
        points, why = check()
        score += points
        reasons.extend(why)
    return score, reasons


if __name__ == '__main__':
    ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    headless_shell = {
        "ua": ua, "platform": "Linux x86_64",
        "uad": {"brands": ["Chromium/153", "Not_A Brand/8"], "mobile": False, "platform": "Linux"},
        "geometry": {"outer_w": 1280, "outer_h": 720, "inner_w": 1280, "inner_h": 720},
        "notification_permission": "denied", "permission_query": "prompt",
        "plugins": 0, "has_chrome_object": False,
        "webgl": {"renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"},
    }
    headers = {"User-Agent": ua, "Sec-CH-UA": '"Chromium";v="153", "Not_A Brand";v="8"',
               "Sec-CH-UA-Platform": '"Linux"'}
    print(score_consistency(headless_shell, headers))
