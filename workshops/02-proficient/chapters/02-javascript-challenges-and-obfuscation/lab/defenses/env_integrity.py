"""
Chapter 2 — Round 4 defense: environment-bound answers (Section 2.5)

Round 3's attacker stopped reading our code and simply ran it in jsdom, a
JavaScript DOM implementation for Node. jsdom runs JavaScript well. What it
doesn't have is a real browser *engine*. At Round 4 the challenge folds three
facts about the engine into the hash (see challenge_template.js):

  1. Layout. A hidden, fixed-size box must report its real offsetWidth.
     jsdom has no layout engine and reports 0. Each variant uses a different
     box size, so there is no single magic number to hard-code.
  2. Native code. `Element.prototype.getBoundingClientRect` must stringify as
     "[native code]". jsdom's DOM methods are JavaScript, and their source
     shows.
  3. Engine consistency. The Error.stack format (V8 "    at f (...)" or
     SpiderMonkey/JSC "f@...") must match the engine that the User-Agent
     claims.

None of these is a fingerprint. Every genuine Chrome, Firefox and Safari gives
the same answer, so there is nothing per-device to track (that's W2 Ch4).

False positives to respect:
  - Layout probes in em/rem units break for users with a minimum-font-size
    or text-zoom setting (an accessibility need). That's why we use px only.
  - Anti-fingerprinting extensions (JShelter, CanvasBlocker and similar)
    wrap DOM methods in JavaScript, and some of them fail native-code checks.
    Probe APIs that those tools rarely wrap, and in production treat a
    failure as a score, not a block.
  - Engine checks keyed on the UA must know every engine: Safari and every
    iOS browser (CriOS, FxiOS) are JavaScriptCore, not V8. The naive rule
    "stack must be V8-style" blocks all Firefox and Safari users. Try it:
        NAIVE_ENGINE_CHECK=1 DEFENSE_LEVEL=4 python demo_site/app.py
  - Timing windows: an old phone, or a laptop on battery saver, can take 5-10x
    longer than your dev machine. Try it:
        MAX_SOLVE_MS=300 DEFENSE_LEVEL=4 python demo_site/app.py
    and watch the throttled user in the checkpoint.

What still beats it: a patched emulator that returns the right offsetWidth
and a fake "[native code]" toString (an arms race you can keep winning for a
while), or simply a real browser (Round 4's attack).
"""

import os

from variants import ENGINE_OTHER, ENGINE_V8, probe_width

NAIVE_ENGINE_CHECK = os.environ.get("NAIVE_ENGINE_CHECK") == "1"
# Time from /challenge/new to /challenge/verify. The token TTL (60 s) is the
# hard limit; this is the policy limit.
MAX_SOLVE_MS = float(os.environ.get("MAX_SOLVE_MS", "30000"))


def expected_engine(user_agent):
    """Which Error.stack style should this User-Agent's engine produce?"""
    ua = user_agent or ""
    if NAIVE_ENGINE_CHECK:
        return ENGINE_V8            # the bug: assumes everyone runs Chrome
    # TODO (Round 4): is this complete? Think about Edge, Opera, Samsung
    # Internet, Chrome on iOS (CriOS) and Firefox on iOS (FxiOS).
    is_chromium = ("Chrome/" in ua or "Chromium/" in ua) and "Firefox/" not in ua
    return ENGINE_V8 if is_chromium else ENGINE_OTHER


def expected_env(probe, user_agent):
    """The (layout_px, native_ok, engine) a genuine browser would fold into the hash."""
    return probe_width(probe), True, expected_engine(user_agent)


def within_window(elapsed_ms):
    return elapsed_ms <= MAX_SOLVE_MS


if __name__ == "__main__":
    chrome = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0"
    safari = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) CriOS/153.0.0.0 Mobile/15E148 Safari/604.1")
    for name, ua in (("Chrome", chrome), ("Firefox", firefox), ("Chrome on iOS", safari)):
        print(f"{name:<14} expects {expected_env((120, 4, 1), ua)}")
