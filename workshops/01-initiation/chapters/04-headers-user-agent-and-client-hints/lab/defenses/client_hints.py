"""
Chapter 4 — Defense Layer 3a: User-Agent Client Hints (Section 4.4)

Chromium browsers (Chrome, Edge, Opera, Brave, Samsung Internet) send three
low-entropy Client Hints on every request to a secure context (HTTPS, or
http://localhost):

    Sec-CH-UA:          "Chromium";v="153", "Not?A_Brand";v="8", "Google Chrome";v="153"
    Sec-CH-UA-Mobile:   ?0
    Sec-CH-UA-Platform: "Windows"

They duplicate what the User-Agent says, which gives us a free consistency
check: brand version vs UA version, platform vs UA OS, mobile flag vs UA.
Firefox and Safari do NOT send Client Hints, so these rules only apply when
the UA claims to be Chromium.

Enabled when DEFENSE_LEVEL >= 3. Catches: Round 3 (copied headers without
hints) and Round 5 (Playwright with a UA override).
"""

import re

# Sec-CH-UA is a Structured Header list: "Brand";v="version", ...
BRAND_RE = re.compile(r'"([^"]*)"\s*;\s*v\s*=\s*"([^"]*)"')

# GREASE brand: "Not" + random punctuation + "A" + punctuation + "Brand"
GREASE_RE = re.compile(r"^Not.?A.?Brand$")

CHROMIUM_UA_RE = re.compile(r"(?:Chrome|Chromium|HeadlessChrome)/(\d+)")
CLIENT_HINTS_SINCE = 89   # Chromium version that shipped Sec-CH-UA by default


def parse_brand_list(value):
    """Parse a Sec-CH-UA / Sec-CH-UA-Full-Version-List value into {brand: version}."""
    return {brand: version for brand, version in BRAND_RE.findall(value or "")}


def platform_from_ua(ua_string):
    """Map a UA string to the Sec-CH-UA-Platform value a real browser would send."""
    if "Android" in ua_string:
        return "Android"
    if "Windows" in ua_string:
        return "Windows"
    if "CrOS" in ua_string:
        return "Chrome OS"
    if "Macintosh" in ua_string or "Mac OS X" in ua_string:
        return "macOS"
    if "Linux" in ua_string or "X11" in ua_string:
        return "Linux"
    return None


def chromium_major(ua_string):
    """Return the Chromium major version claimed by the UA, or None if not Chromium."""
    if "CriOS" in ua_string:      # Chrome on iOS is WebKit: no Client Hints
        return None
    m = CHROMIUM_UA_RE.search(ua_string)
    return int(m.group(1)) if m else None


def score_client_hints(headers, secure_context=True):
    """
    Layer 3a: check the low-entropy Client Hints against the User-Agent.

    `secure_context` must be False for plain-HTTP, non-localhost requests,
    where browsers withhold hints. Returns (score, reasons).
    """
    h = {k.lower(): v for k, v in headers.items()}
    ua_string = h.get("user-agent", "")
    sec_ch_ua = h.get("sec-ch-ua")
    score = 0
    reasons = []

    if not secure_context:
        return 0, []

    major = chromium_major(ua_string)

    # 1. Non-Chromium UA that sends Chromium-only hints
    if major is None:
        if sec_ch_ua:
            score += 30
            reasons.append("UA is not Chromium but Sec-CH-UA is present (Chromium-only header)")
        return score, reasons

    if major < CLIENT_HINTS_SINCE:
        return score, reasons

    # 2. Chromium UA without hints
    if not sec_ch_ua:
        score += 30
        reasons.append(f"UA claims Chromium {major} but Sec-CH-UA is absent")
        return score, reasons

    brands = parse_brand_list(sec_ch_ua)

    # 3. Headless brand leak
    if "HeadlessChrome" in brands:
        score += 40
        reasons.append("Sec-CH-UA brand list contains HeadlessChrome")

    # 4. GREASE: real Chromium always inserts a fake brand to keep parsers honest
    if not any(GREASE_RE.match(b) for b in brands):
        score += 15
        reasons.append("Sec-CH-UA has no GREASE brand (hand-written value?)")

    # 5. Brand version must match the UA major version
    chromium_version = brands.get("Chromium") or brands.get("HeadlessChrome")
    if chromium_version and chromium_version.split(".")[0] != str(major):
        score += 30
        reasons.append(f"Sec-CH-UA says Chromium {chromium_version} but UA says {major}")

    # 6. Platform must match the UA OS
    platform = h.get("sec-ch-ua-platform", "").strip('"')
    expected_platform = platform_from_ua(ua_string)
    if not platform:
        score += 10
        reasons.append("Sec-CH-UA-Platform is absent")
    elif expected_platform and platform != expected_platform:
        score += 30
        reasons.append(f"Sec-CH-UA-Platform is {platform} but UA says {expected_platform}")

    # 7. Mobile flag must match the UA
    mobile = h.get("sec-ch-ua-mobile")
    ua_is_mobile = "Mobile" in ua_string
    if mobile in ("?0", "?1") and (mobile == "?1") != ua_is_mobile:
        score += 20
        reasons.append(f"Sec-CH-UA-Mobile={mobile} contradicts the UA")

    return score, reasons


if __name__ == '__main__':
    win_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    samples = {
        "Real Chrome 153 on Windows": {
            "User-Agent": win_ua,
            "Sec-CH-UA": '"Google Chrome";v="153", "Not?A_Brand";v="8", "Chromium";v="153"',
            "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"',
        },
        "Copied headers, no hints": {"User-Agent": win_ua},
        "Headless Chromium on Linux, UA overridden via CDP without metadata": {
            "User-Agent": win_ua,
            "Sec-CH-UA": '"Chromium";v="153", "Not?A_Brand";v="24", "HeadlessChrome";v="153"',
            "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Linux"',
        },
        "Hand-written hints": {
            "User-Agent": win_ua,
            "Sec-CH-UA": '"Google Chrome";v="124", "Chromium";v="124"',
            "Sec-CH-UA-Mobile": "?1", "Sec-CH-UA-Platform": '"Windows"',
        },
        "Firefox (no hints, correctly)": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
        },
    }
    for label, headers in samples.items():
        score, reasons = score_client_hints(headers)
        print(f"\n{label}: score={score}")
        for r in reasons:
            print(f"  - {r}")
