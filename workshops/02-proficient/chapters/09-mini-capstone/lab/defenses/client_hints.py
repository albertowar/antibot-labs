"""
Chapter 2, Round 3 defense (L3a): User-Agent Client Hints.

Chromium browsers (Chrome, Edge, Opera, Brave, Samsung Internet) send three low-entropy Client Hints
on every request to a secure context (HTTPS, or http://localhost):

    Sec-CH-UA:          "Chromium";v="153", "Not?A_Brand";v="8", "Google Chrome";v="153"
    Sec-CH-UA-Mobile:   ?0
    Sec-CH-UA-Platform: "Windows"

They duplicate what the User-Agent says, which gives a free consistency check: brand version vs UA
version, platform vs UA OS, mobile flag vs UA. Firefox and Safari do NOT send Client Hints, so these
rules only apply when the UA claims to be Chromium.

What it catches: Round 3 (copied headers without hints) and a headless Chromium with a UA override
(Round 5: the override changes the string, not the brand list Chromium builds from the real binary).

What it misses: a bot that writes the three hints by hand and gets them right (Round 4).

Who it hurts: very few. Chromium-based browsers behind a proxy that strips `Sec-CH-*`, and browser
extensions that spoof the UA without the hints (they look exactly like a bot here).

    python -m defenses.client_hints      # from the lab folder
"""

import re

from .header_util import demo_ctx, lowered, note_reasons, secure_context, show
from .pipeline import Check, Signal

BRAND_RE = re.compile(r'"([^"]*)"\s*;\s*v\s*=\s*"([^"]*)"')      # Sec-CH-UA is a Structured Header list
GREASE_RE = re.compile(r"^Not.?A.?Brand$")                       # "Not" + punctuation + "A" + punctuation + "Brand"
CHROMIUM_UA_RE = re.compile(r"(?:Chrome|Chromium|HeadlessChrome)/(\d+)")
CLIENT_HINTS_SINCE = 89                                          # Chromium version that shipped Sec-CH-UA by default


def parse_brand_list(value):
    """Parse a Sec-CH-UA / Sec-CH-UA-Full-Version-List value into {brand: version}."""
    return {brand: version for brand, version in BRAND_RE.findall(value or "")}


def platform_from_ua(ua_string):
    """The Sec-CH-UA-Platform value a real browser would send for this UA."""
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
    """The Chromium major version claimed by the UA, or None if it is not Chromium."""
    if "CriOS" in ua_string:          # Chrome on iOS is WebKit: no Client Hints
        return None
    m = CHROMIUM_UA_RE.search(ua_string)
    return int(m.group(1)) if m else None


def score_client_hints(h, secure=True):
    """Check the low-entropy Client Hints (a lower-cased header dict) against the User-Agent."""
    ua_string, sec_ch_ua = h.get("user-agent", ""), h.get("sec-ch-ua")
    signals = []
    if not secure:                    # plain HTTP off localhost: browsers withhold the hints
        return signals
    major = chromium_major(ua_string)

    if major is None:                 # 1. a non-Chromium UA that sends Chromium-only hints
        if sec_ch_ua:
            signals.append(Signal("client_hints", "hints_on_non_chromium", 30, "UA is not Chromium but Sec-CH-UA is present (Chromium-only header)"))
        return signals
    if major < CLIENT_HINTS_SINCE:
        return signals

    if not sec_ch_ua:                 # 2. a Chromium UA without hints
        return [Signal("client_hints", "hints_absent", 30, f"UA claims Chromium {major} but Sec-CH-UA is absent")]

    brands = parse_brand_list(sec_ch_ua)
    if "HeadlessChrome" in brands:    # 3. headless brand leak
        signals.append(Signal("client_hints", "headless_brand", 40, "Sec-CH-UA brand list contains HeadlessChrome"))
    if not any(GREASE_RE.match(b) for b in brands):   # 4. real Chromium always inserts a fake brand
        signals.append(Signal("client_hints", "no_grease", 15, "Sec-CH-UA has no GREASE brand (hand-written value?)"))
    chromium_version = brands.get("Chromium") or brands.get("HeadlessChrome")     # 5. brand version == UA major
    if chromium_version and chromium_version.split(".")[0] != str(major):
        signals.append(Signal("client_hints", "version_mismatch", 30, f"Sec-CH-UA says Chromium {chromium_version} but UA says {major}"))

    platform = h.get("sec-ch-ua-platform", "").strip('"')                         # 6. platform == UA OS
    expected = platform_from_ua(ua_string)
    if not platform:
        signals.append(Signal("client_hints", "platform_absent", 10, "Sec-CH-UA-Platform is absent"))
    elif expected and platform != expected:
        signals.append(Signal("client_hints", "platform_mismatch", 30, f"Sec-CH-UA-Platform is {platform} but UA says {expected}"))

    mobile = h.get("sec-ch-ua-mobile")                                            # 7. mobile flag == UA
    if mobile in ("?0", "?1") and (mobile == "?1") != ("Mobile" in ua_string):
        signals.append(Signal("client_hints", "mobile_mismatch", 20, f"Sec-CH-UA-Mobile={mobile} contradicts the UA"))
    return signals


def _check(ctx):
    signals = score_client_hints(lowered(ctx), secure_context(ctx))
    note_reasons(ctx, signals)
    return signals


CHECK = Check("client_hints", _check, phases=("request",))


if __name__ == "__main__":
    win_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    samples = {
        "Real Chrome 153 on Windows": {
            "User-Agent": win_ua,
            "Sec-CH-UA": '"Google Chrome";v="153", "Not?A_Brand";v="8", "Chromium";v="153"',
            "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"',
        },
        "Copied headers, no hints": {"User-Agent": win_ua},
        "Headless Chromium on Linux, UA overridden without metadata": {
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
        show(label, _check(demo_ctx(headers)))
