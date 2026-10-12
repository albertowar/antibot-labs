"""
Workshop 1, Chapter 4 — Defense Layer 4: Accept-CH Negotiation (Section 4.4.4)

High-entropy Client Hints are only sent when the server asks for them. The
server answers with

    Accept-CH: Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch

and a real Chromium browser remembers that preference for the origin and
attaches those hints to every following request. A script that replays a
static set of headers does not take part in the negotiation, so after we have
asked once (tracked with a cookie) a "Chrome" that never sends them is lying.

When the hints do arrive we cross-check them as well: the UA string is
frozen ("Chrome/153.0.0.0", "Windows NT 10.0") but the full version list and
platform version are not.

In W1 Ch4 this was enabled at DEFENSE_LEVEL >= 4. In W2 Ch1 it is always on (edge_rules.py).
"""

import re

from client_hints import chromium_major, parse_brand_list, platform_from_ua

HIGH_ENTROPY_HINTS = [
    "Sec-CH-UA-Full-Version-List",
    "Sec-CH-UA-Platform-Version",
    "Sec-CH-UA-Arch",
]
ACCEPT_CH_VALUE = ", ".join(HIGH_ENTROPY_HINTS)
OFFERED_COOKIE = "ch_offered"

# Browsers report e.g. "15.0.0" (Windows 11), "15.1.0" (macOS); emulators often send "10.0"
PLATFORM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def score_accept_ch(headers, cookies, secure_context=True):
    """
    Layer 4: after Accept-CH has been offered, require and verify the
    high-entropy hints. Returns (score, reasons).
    """
    h = {k.lower(): v for k, v in headers.items()}
    ua_string = h.get("user-agent", "")
    major = chromium_major(ua_string)
    score = 0
    reasons = []

    if major is None or not secure_context:
        return 0, []

    # 1. First contact: nothing to check yet (the response will carry Accept-CH)
    if OFFERED_COOKIE not in cookies:
        return 0, []

    missing = [name for name in HIGH_ENTROPY_HINTS if not h.get(name.lower())]
    if len(missing) == len(HIGH_ENTROPY_HINTS):
        score += 40
        reasons.append("Accept-CH was offered but the client ignored it (no high-entropy hints)")
        return score, reasons
    if missing:
        score += 15
        reasons.append(f"Some requested hints missing: {', '.join(missing)}")

    # 2. Full version list: must agree with the frozen UA major and must NOT be frozen itself
    full = parse_brand_list(h.get("sec-ch-ua-full-version-list", ""))
    chromium_full = full.get("Chromium") or full.get("HeadlessChrome")
    if chromium_full:
        if chromium_full.split(".")[0] != str(major):
            score += 30
            reasons.append(f"Full-Version-List says {chromium_full} but UA says {major}")
        if chromium_full.endswith(".0.0.0"):
            score += 20
            reasons.append(f"Full-Version-List is frozen ({chromium_full}); real browsers send the build number")

    # 3. Platform version must be plausible for the platform
    platform = h.get("sec-ch-ua-platform", "").strip('"') or platform_from_ua(ua_string)
    platform_version = h.get("sec-ch-ua-platform-version", "").strip('"')
    if platform_version and not PLATFORM_VERSION_RE.match(platform_version):
        score += 15
        reasons.append(f"Platform-Version '{platform_version}' is not in browser format (major.minor.patch)")
    if platform == "Windows" and platform_version:
        win_major = platform_version.split(".")[0]
        if win_major == "0":
            score += 20
            reasons.append("Platform-Version 0.x is Windows 7/8, which current Chrome no longer supports")

    return score, reasons


if __name__ == '__main__':
    win_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    low_entropy = {
        "User-Agent": win_ua,
        "Sec-CH-UA": '"Google Chrome";v="153", "Not?A_Brand";v="8", "Chromium";v="153"',
        "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"',
    }
    samples = {
        "First visit (no cookie yet)": (low_entropy, {}),
        "Replay bot after Accept-CH": (low_entropy, {OFFERED_COOKIE: "1"}),
        "Real Chrome after Accept-CH": ({
            **low_entropy,
            "Sec-CH-UA-Full-Version-List":
                '"Google Chrome";v="153.0.7390.108", "Not?A_Brand";v="8.0.0.0", "Chromium";v="153.0.7390.108"',
            "Sec-CH-UA-Platform-Version": '"19.0.0"',
            "Sec-CH-UA-Arch": '"x86"',
        }, {OFFERED_COOKIE: "1"}),
        "Bot faking hints lazily": ({
            **low_entropy,
            "Sec-CH-UA-Full-Version-List": '"Google Chrome";v="153.0.0.0", "Chromium";v="153.0.0.0"',
            "Sec-CH-UA-Platform-Version": '"0.3.0"',
            "Sec-CH-UA-Arch": '"x86"',
        }, {OFFERED_COOKIE: "1"}),
    }
    for label, (headers, cookies) in samples.items():
        score, reasons = score_accept_ch(headers, cookies)
        print(f"\n{label}: score={score}")
        for r in reasons:
            print(f"  - {r}")
