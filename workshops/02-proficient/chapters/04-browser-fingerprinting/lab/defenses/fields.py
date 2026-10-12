"""
Chapter 4 — Reading a Fingerprint Payload (Section 4.2)

Small helpers shared by every defense layer. They turn the collector's raw
observations into a few normalised fields: the OS the client claims, the
GPU model behind the WebGL renderer string, whether that renderer is a
software rasteriser, and so on.

Trade-off: every normaliser is a lookup table that someone has to maintain.
GPU strings, OS names and browser brands change every few months. When a
rule starts misfiring, check these tables before blaming the rule.
"""

import re

SOFTWARE_RENDERERS = re.compile(
    r"llvmpipe|softpipe|lavapipe|Microsoft Basic Render|WARP|Software Rasterizer", re.I)
SWIFTSHADER = re.compile(r"SwiftShader", re.I)
DESKTOP_OSES = {"Windows", "macOS", "Linux", "ChromeOS"}
# Operating systems that always ship at least one speech-synthesis voice
OSES_WITH_VOICES = {"Windows", "macOS", "iOS", "Android"}


def os_from_ua(ua):
    """The OS a User-Agent string claims (frozen by UA reduction, see W1 Ch3)."""
    ua = ua or ""
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Android" in ua:
        return "Android"
    if "Windows" in ua:
        return "Windows"
    if "Mac OS X" in ua or "Macintosh" in ua:
        return "macOS"
    if "CrOS" in ua:
        return "ChromeOS"
    if "Linux" in ua or "X11" in ua:
        return "Linux"
    return "unknown"


def os_from_platform(platform):
    """The OS behind navigator.platform ("Win32", "MacIntel", "Linux x86_64", ...)."""
    p = (platform or "").lower()
    if p.startswith("win"):
        return "Windows"
    if p.startswith("mac"):
        return "macOS"
    if p in ("iphone", "ipad", "ipod"):
        return "iOS"
    if "android" in p or "linux arm" in p or "linux aarch64" in p:
        return "Android or Linux"
    if p.startswith("linux"):
        return "Linux"
    if p.startswith("cros"):
        return "ChromeOS"
    return "unknown"


def renderer(fp):
    """The most specific WebGL renderer string the client exposed."""
    webgl = fp.get("webgl") or {}
    return webgl.get("unmaskedRenderer") or webgl.get("renderer") or ""


def gpu_model(renderer_string):
    """
    Reduce a renderer string to a GPU model, so that equal hardware compares
    equal across graphics APIs and driver builds:

      ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 ...)  -> NVIDIA GeForce RTX 3060
      ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)   -> Apple M2
      Apple GPU                                                            -> Apple GPU
    """
    r = renderer_string or ""
    if is_swiftshader(r):
        return "SwiftShader"
    if is_software_renderer(r):
        return "software"
    m = re.match(r"ANGLE \(([^,]*),\s*(.*)\)\s*$", r)
    if m:
        r = m.group(2)
        r = re.sub(r"^ANGLE Metal Renderer:\s*", "", r)
        r = re.split(r",\s*(?:Unspecified Version|OpenGL|D3D|Direct3D|Vulkan)", r)[0]
        r = re.sub(r"\s*\(0x[0-9A-Fa-f]+\)", "", r)
        r = re.sub(r"\s+(?:Direct3D\d+|OpenGL|Vulkan).*$", "", r)
        r = re.sub(r"^D3D12 \((.*)\)$", r"\1", r)
    return r.strip() or "none"


def is_swiftshader(renderer_string):
    return bool(SWIFTSHADER.search(renderer_string or ""))


def is_software_renderer(renderer_string):
    return bool(SOFTWARE_RENDERERS.search(renderer_string or ""))


def brand_set(brands):
    """{"Google Chrome/153", "Chromium/153", ...} from either the JS list or the header."""
    return {b.strip() for b in brands or [] if b and b.strip()}


def parse_sec_ch_ua(header):
    """'"Chromium";v="153", "Not_A Brand";v="8"' -> {"Chromium/153", "Not_A Brand/8"}"""
    return {f"{brand}/{version}"
            for brand, version in re.findall(r'"([^"]+)";v="([^"]+)"', header or "")}


def primary_language(value):
    """'en-GB,en;q=0.9' -> 'en'"""
    first = (value or "").split(",")[0].split(";")[0].strip()
    return first.split("-")[0].lower()


if __name__ == '__main__':
    for r in ["ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)",
              "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
              "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",
              "ANGLE (Microsoft Corporation, D3D12 (NVIDIA GeForce RTX 3060), OpenGL 4.2)",
              "ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)",
              "Apple GPU", "llvmpipe (LLVM 17.0.6, 256 bits)"]:
        print(f"{gpu_model(r):<28} swiftshader={is_swiftshader(r)!s:<5} software={is_software_renderer(r)}  <- {r}")
