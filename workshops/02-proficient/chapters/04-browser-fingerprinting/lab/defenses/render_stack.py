"""
Chapter 4 — L1: Render-Stack Plausibility (Section 4.3, Round 1)

Asks one question: could this payload have come from a real device's
graphics, audio and speech stack? Headless browsers on servers have no GPU
and no OS voices, and they show it.

    SwiftShader WebGL renderer             +40  bot on its own (see below)
    Other software renderer (llvmpipe...)  +15  VDI and GPU-less VMs are real users
    WebGL unavailable                      +15  GPU blocklisted / acceleration off
    Canvas unavailable                     +20
    OfflineAudioContext unavailable        +10
    No voices on an OS that ships voices   +15  Linux has none by default: no points

Why SwiftShader may block alone: since Chrome 139, Chrome no longer falls
back to SwiftShader for WebGL. A real Chrome without a usable GPU now gets
*no* WebGL. A SwiftShader renderer therefore means someone passed
--enable-unsafe-swiftshader, which is what automation frameworks do.
Exceptions exist (test rigs, an enterprise policy that re-enables it) and
are small enough to live with, but watch your false-positive numbers.

Why llvmpipe may not block: Mesa's llvmpipe is what Firefox and Chromium
on Linux report inside VDI sessions and GPU-less VMs. Those are paying
customers on locked-down corporate desktops. Score it, never block on it.

False positives to expect: VDI and remote-desktop users, users who turned
off hardware acceleration, very old GPUs on the blocklist, and kiosks.
None of them should reach the bot threshold through L1 alone.
"""

from fields import (OSES_WITH_VOICES, is_software_renderer, is_swiftshader, os_from_ua,
                    renderer)

SWIFTSHADER_POINTS = 40
SOFTWARE_RENDERER_POINTS = 15
NO_WEBGL_POINTS = 15
NO_CANVAS_POINTS = 20
NO_AUDIO_POINTS = 10
NO_VOICES_POINTS = 15


def score_render_stack(fp):
    """Return (points, reasons) for one fingerprint payload."""
    points, reasons = 0, []
    webgl = fp.get("webgl") or {}
    gl_renderer = renderer(fp)
    claimed_os = os_from_ua((fp.get("nav") or {}).get("userAgent"))

    if not webgl.get("supported"):
        points += NO_WEBGL_POINTS
        reasons.append("WebGL unavailable")
    elif is_swiftshader(gl_renderer):
        points += SWIFTSHADER_POINTS
        reasons.append("SwiftShader WebGL renderer (needs --enable-unsafe-swiftshader since Chrome 139)")
    elif is_software_renderer(gl_renderer):
        points += SOFTWARE_RENDERER_POINTS
        reasons.append(f"Software WebGL renderer: {gl_renderer[:60]}")

    if not (fp.get("canvas") or {}).get("supported"):
        points += NO_CANVAS_POINTS
        reasons.append("Canvas 2D unavailable")

    if not (fp.get("audio") or {}).get("supported"):
        points += NO_AUDIO_POINTS
        reasons.append("OfflineAudioContext unavailable")

    voices = fp.get("voices") or {}
    # TODO (Round 1): Android WebView and some de-Googled Android builds ship
    # no voices. Add a profile that shows it, then decide whether Android
    # belongs in OSES_WITH_VOICES.
    if voices.get("count", 0) == 0 and claimed_os in OSES_WITH_VOICES:
        points += NO_VOICES_POINTS
        reasons.append(f"No speech voices, but the UA claims {claimed_os}")

    return points, reasons


if __name__ == '__main__':
    headless = {
        "nav": {"userAgent": "Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/153.0.8010.12 ..."},
        "webgl": {"supported": True, "unmaskedRenderer":
                  "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"},
        "canvas": {"supported": True}, "audio": {"supported": True}, "voices": {"count": 0},
    }
    vdi = {
        "nav": {"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/153.0.0.0 ..."},
        "webgl": {"supported": True, "unmaskedRenderer":
                  "ANGLE (Microsoft, Microsoft Basic Render Driver (0x0000008C) Direct3D11 vs_5_0 ps_5_0, D3D11)"},
        "canvas": {"supported": True}, "audio": {"supported": True}, "voices": {"count": 3},
    }
    for name, fp in [("default headless", headless), ("Citrix VDI user", vdi)]:
        print(name, score_render_stack(fp))
