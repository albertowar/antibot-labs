"""
Chapter 4 — L2: Lie Detection (Section 4.4, Round 2)

A spoofer can make any single value say anything. What is hard is making
every *view* of that value agree. L2 compares views that a JS-level patch
rarely reaches all at once:

    Patched natives look non-native (toString/prototype/new)   +25
    Properties defined on the navigator instance               +25
    Page vs. Web Worker disagree (platform, cores, GPU, ...)   +40  fingerprint_mismatch
    Claimed desktop GPU with software-renderer limits          +20  fingerprint_mismatch
    JS userAgentData vs. Sec-CH-UA headers disagree            +30  fingerprint_mismatch
    navigator.userAgent vs. User-Agent header disagree         +30  fingerprint_mismatch
    UA OS vs. navigator.platform disagree                      +30  fingerprint_mismatch
    navigator.languages vs. Accept-Language disagree           +10

The shape check catches only careless patches. A stealth plugin wraps the
native function in a Proxy, which keeps "[native code]", has no `prototype`
and can't be constructed, exactly like the original. That is why L2 relies
mostly on cross-context and cross-signal checks: the worker runs its own
navigator and WebGL, and the headers are produced by the network stack,
not by page JavaScript.

The signal name `fp:fingerprint_mismatch` is what Chapter 8 feeds into its risk engine.

False positives to expect:
  - Privacy extensions patch canvas and WebGL methods with plain functions,
    which fails the shape check. That's why a tampered native alone scores
    25 (suspicious) and not 40: a careless patch is a weak bot signal and a
    common human one.
  - Privacy browsers that randomise *consistently* (Brave, Firefox FPP,
    Safari AFP) pass, because the engine spoofs every context the same way.
    A privacy extension that patches only the page would fail the worker
    check. Log those reasons before you block on them.
  - Language: travellers and expats legitimately set Accept-Language and
    the OS language differently, so that check stays at 10 points.
  - Firefox and Safari don't implement userAgentData or Sec-CH-UA, so those
    checks simply don't run for them.
"""

from . import fingerprint
from .fields import (DESKTOP_OSES, brand_set, os_from_platform, os_from_ua, parse_sec_ch_ua,
                     primary_language, renderer)
from .pipeline import Check

TAMPERED_POINTS = 25
OWN_PROPS_POINTS = 25
WORKER_POINTS = 40
WEBGL_LIMITS_POINTS = 20
CLIENT_HINTS_POINTS = 30
UA_HEADER_POINTS = 30
PLATFORM_POINTS = 30
LANGUAGE_POINTS = 10

HARDWARE_GPU_WORDS = ("NVIDIA", "GeForce", "Radeon", "AMD", "Intel", "Apple M")
# Every desktop GPU from the last decade supports 16384×16384 textures.
# SwiftShader and llvmpipe report 8192.
MIN_HARDWARE_TEXTURE_SIZE = 16384
WORKER_FIELDS = [
    # (worker key, how to read the same value on the page)
    ("platform", lambda fp: (fp.get("nav") or {}).get("platform")),
    ("hardwareConcurrency", lambda fp: (fp.get("nav") or {}).get("hardwareConcurrency")),
    ("deviceMemory", lambda fp: (fp.get("nav") or {}).get("deviceMemory")),
    ("userAgent", lambda fp: (fp.get("nav") or {}).get("userAgent")),
    ("uadPlatform", lambda fp: (fp.get("uad") or {}).get("platform")),
    ("webglRenderer", renderer),
    # TODO (Round 2, optional tuning): languages and timeZone are in the worker payload too.
    # Add them, run the checkpoint, and check that no real-user profile breaks.
]


def tampered_natives(lies):
    """Names of getters/methods whose shape no longer looks native."""
    found = []
    shapes = {**{f"Navigator.{k}": v for k, v in (lies.get("navGetters") or {}).items()},
              **(lies.get("methods") or {})}
    for name, shape in shapes.items():
        if not shape.get("present"):
            continue
        if not shape.get("nativeSource") or shape.get("hasPrototype") or shape.get("constructible"):
            found.append(name)
    return found


def worker_mismatches(fp):
    worker = fp.get("worker") or {}
    if "error" in worker or not worker:
        return None
    diffs = []
    for key, page_value in WORKER_FIELDS:
        page, wk = page_value(fp), worker.get(key)
        if page in (None, "") or wk in (None, ""):
            continue  # not exposed in one of the contexts (e.g. Firefox has no deviceMemory)
        if page != wk:
            diffs.append(f"{key}: page {str(page)[:40]!r} vs worker {str(wk)[:40]!r}")
    return diffs


def score_lies(fp, headers):
    """
    Return (points, reasons) for one payload and the headers of the request
    that carried it. `headers` is any case-insensitive mapping.
    """
    points, reasons = 0, []
    nav = fp.get("nav") or {}
    lies = fp.get("lies") or {}
    ua = nav.get("userAgent") or ""
    claimed_os = os_from_ua(ua)

    tampered = tampered_natives(lies)
    if tampered:
        points += TAMPERED_POINTS
        reasons.append(f"Patched natives: {', '.join(tampered[:4])}")

    own = lies.get("navigatorOwnProps") or []
    if own:
        points += OWN_PROPS_POINTS
        reasons.append(f"navigator has own properties: {', '.join(own[:5])}")

    diffs = worker_mismatches(fp)
    if diffs:
        points += WORKER_POINTS
        reasons.append("fingerprint_mismatch: page and worker disagree on " + "; ".join(diffs[:3]))
    elif diffs is None and fp.get("uad"):
        reasons.append("note: no worker data from a Chromium-based browser")

    webgl = fp.get("webgl") or {}
    gl_renderer = renderer(fp)
    if (webgl.get("supported") and claimed_os in DESKTOP_OSES
            and any(w in gl_renderer for w in HARDWARE_GPU_WORDS)
            and (webgl.get("maxTextureSize") or 0) < MIN_HARDWARE_TEXTURE_SIZE):
        points += WEBGL_LIMITS_POINTS
        reasons.append(f"fingerprint_mismatch: renderer claims hardware GPU but "
                       f"MAX_TEXTURE_SIZE={webgl.get('maxTextureSize')}")

    uad = fp.get("uad")
    header_brands = parse_sec_ch_ua(headers.get("Sec-CH-UA"))
    if uad and header_brands:
        js_brands = brand_set(uad.get("brands"))
        header_platform = (headers.get("Sec-CH-UA-Platform") or "").strip('"')
        problems = []
        if js_brands != header_brands:
            problems.append(f"brands JS {sorted(js_brands)} vs header {sorted(header_brands)}")
        if header_platform and uad.get("platform") != header_platform:
            problems.append(f"platform JS {uad.get('platform')!r} vs header {header_platform!r}")
        if problems:
            points += CLIENT_HINTS_POINTS
            reasons.append("fingerprint_mismatch: userAgentData vs Sec-CH-UA: " + "; ".join(problems))

    header_ua = headers.get("User-Agent")
    if header_ua and ua and header_ua != ua:
        points += UA_HEADER_POINTS
        reasons.append("fingerprint_mismatch: navigator.userAgent differs from the User-Agent header")

    platform_os = os_from_platform(nav.get("platform"))
    if (claimed_os != "unknown" and platform_os != "unknown"
            and claimed_os not in platform_os):
        points += PLATFORM_POINTS
        reasons.append(f"fingerprint_mismatch: UA says {claimed_os}, "
                       f"navigator.platform says {nav.get('platform')!r}")

    accept_language = headers.get("Accept-Language")
    languages = nav.get("languages") or []
    if accept_language and languages:
        if primary_language(accept_language) != primary_language(languages[0]):
            points += LANGUAGE_POINTS
            reasons.append(f"Accept-Language {accept_language.split(',')[0]!r} vs "
                           f"navigator.languages[0] {languages[0]!r}")

    return points, reasons


def evaluate(ctx):
    """(points, reasons) for this session's record and the headers its payload arrived with."""
    rec = fingerprint.record(ctx)
    return score_lies(rec["payload"], fingerprint.Headers(rec["headers"]))


def _check(ctx):
    if fingerprint.record(ctx) is None:
        return None
    points, reasons = evaluate(ctx)
    name = "fingerprint_mismatch" if any(r.startswith("fingerprint_mismatch") for r in reasons) else "tampered"
    return fingerprint.signals("L2", name, points, reasons, ctx)


CHECK = Check("lie_detector", _check, phases=("action:register",))


if __name__ == '__main__':
    patched = {
        "nav": {"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                "platform": "Win32", "hardwareConcurrency": 8, "deviceMemory": 8, "languages": ["en-US"]},
        "uad": {"brands": ["Google Chrome/153", "Not_A Brand/8", "Chromium/153"], "platform": "Windows"},
        "webgl": {"supported": True, "maxTextureSize": 8192, "unmaskedRenderer":
                  "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)"},
        "worker": {"platform": "Linux x86_64", "hardwareConcurrency": 12, "deviceMemory": 16,
                   "webglRenderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device ...), SwiftShader driver)"},
        "lies": {"navigatorOwnProps": [], "navGetters": {}, "methods": {}},
    }
    headers = {"User-Agent": patched["nav"]["userAgent"],
               "Sec-CH-UA": '"HeadlessChrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
               "Sec-CH-UA-Platform": '"Windows"'}
    points, reasons = score_lies(patched, headers)
    print(f"Proxy-patched headless Chromium: {points} points")
    for r in reasons:
        print("  -", r)
