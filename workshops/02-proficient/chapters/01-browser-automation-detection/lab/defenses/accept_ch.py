"""
Chapter 2, Round 4 defense (L4): Accept-CH negotiation.

High-entropy Client Hints are only sent when the server asks for them. The store answers every HTML page
with (demo_site/ext/headers.py, at level 4 and above):

    Accept-CH: Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch

and a real Chromium browser remembers that preference for the origin and attaches those hints to every
following request. A script that replays a static set of headers does not take part in the negotiation,
so after the store has asked once (it remembers that in the `ch_offered` cookie) a "Chrome" that never
sends them is lying.

When the hints do arrive they are cross-checked as well: the UA string is frozen ("Chrome/153.0.0.0",
"Windows NT 10.0") but the full version list and platform version are not.

What it catches: Round 4 (consistent low-entropy hints, Chrome order, a plausible Sec-Fetch context).

What it misses: a bot that drops the cookie on every request, so the store never "offered" (Chapter 3:
sessions), a real browser driven by automation, and Round 4's bot once it implements the negotiation
(it is ten lines).

Who it hurts: Chromium users who block cookies or run extensions that strip `Sec-CH-*`; a user whose
cookie is older than the browser's memory of the preference; and an API client built into a Chromium
shell that never navigates. The cookie costs a Set-Cookie per page for every visitor.

    python -m defenses.accept_ch      # from the lab folder
"""

import re

from . import client_hints, policy
from .header_util import demo_ctx, lowered, note_reasons, secure_context, show
from .pipeline import Check, Signal

# Browsers report e.g. "15.0.0" (Windows 11), "15.1.0" (macOS); emulators often send "10.0". Linux sends "".
PLATFORM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def score_accept_ch(h, cookies, secure=True):
    """After Accept-CH has been offered, require and verify the high-entropy hints (lower-cased header dict)."""
    ua_string = h.get("user-agent", "")
    major = client_hints.chromium_major(ua_string)
    signals = []
    if major is None or not secure:
        return signals
    if policy.OFFERED_COOKIE not in cookies:           # first contact: nothing to check yet, the response will carry Accept-CH
        return signals

    wanted = policy.ACCEPT_CH_HINTS
    missing = [name for name in wanted if not h.get(name.lower())]
    if len(missing) == len(wanted):
        return [Signal("accept_ch", "ignored", 40, "Accept-CH was offered but the client ignored it (no high-entropy hints)")]
    if missing:
        signals.append(Signal("accept_ch", "partial", 15, f"Some requested hints missing: {', '.join(missing)}"))

    # Full version list: must agree with the frozen UA major and must NOT be frozen itself
    full = client_hints.parse_brand_list(h.get("sec-ch-ua-full-version-list", ""))
    chromium_full = full.get("Chromium") or full.get("HeadlessChrome")
    if chromium_full:
        if chromium_full.split(".")[0] != str(major):
            signals.append(Signal("accept_ch", "version_mismatch", 30, f"Full-Version-List says {chromium_full} but UA says {major}"))
        if chromium_full.endswith(".0.0.0"):
            signals.append(Signal("accept_ch", "frozen_version", 20, f"Full-Version-List is frozen ({chromium_full}); real browsers send the build number"))

    # Platform version must be plausible for the platform
    platform = h.get("sec-ch-ua-platform", "").strip('"') or client_hints.platform_from_ua(ua_string)
    platform_version = h.get("sec-ch-ua-platform-version", "").strip('"')
    if platform_version and not PLATFORM_VERSION_RE.match(platform_version):
        signals.append(Signal("accept_ch", "bad_platform_version", 15, f"Platform-Version '{platform_version}' is not in browser format (major.minor.patch)"))
    if platform == "Windows" and platform_version.split(".")[0] == "0":
        signals.append(Signal("accept_ch", "win7_platform", 20, "Platform-Version 0.x is Windows 7/8, which current Chrome no longer supports"))
    return signals


def _check(ctx):
    signals = score_accept_ch(lowered(ctx), ctx.cookies, secure_context(ctx))
    note_reasons(ctx, signals)
    return signals


CHECK = Check("accept_ch", _check, phases=("request",))


if __name__ == "__main__":
    win_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    low = {"User-Agent": win_ua, "Sec-CH-UA": '"Google Chrome";v="153", "Not?A_Brand";v="8", "Chromium";v="153"',
           "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"'}
    offered = {policy.OFFERED_COOKIE: "1"}
    samples = {
        "First visit (no cookie yet)": (low, {}),
        "Replay bot after Accept-CH": (low, offered),
        "Real Chrome after Accept-CH": ({**low,
            "Sec-CH-UA-Full-Version-List": '"Google Chrome";v="153.0.7390.108", "Not?A_Brand";v="8.0.0.0", "Chromium";v="153.0.7390.108"',
            "Sec-CH-UA-Platform-Version": '"19.0.0"', "Sec-CH-UA-Arch": '"x86"'}, offered),
        "Bot faking the hints lazily": ({**low,
            "Sec-CH-UA-Full-Version-List": '"Google Chrome";v="153.0.0.0", "Chromium";v="153.0.0.0"',
            "Sec-CH-UA-Platform-Version": '"0.3.0"', "Sec-CH-UA-Arch": '"x86"'}, offered),
    }
    for label, (headers, cookies) in samples.items():
        show(label, _check(demo_ctx(headers, cookies)))
