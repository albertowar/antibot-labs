"""
W1 Ch8 — Header templates for real browsers, in wire order.

Built from the W1 Ch3 captures in tools/profiles/ (Chrome 145, Firefox 155)
and generalised to other versions and platforms. The shopper simulator uses
them to look like the browsers real customers run.

Attackers use them too: copying a real browser's headers out of DevTools is
the first thing any scraper learns (W1 Ch3, Round 3). That is the point.
Headers are free to forge; the layers below them are not.

Each function returns a list of (name, value) pairs. `kind` is:
    "typed"   a navigation from the address bar or a link from elsewhere
    "link"    a same-origin navigation (Referer = previous page)
    "post"    a same-origin form submission
"""

CHROME_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                 "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
CHROME_OS = {
    "windows": ("Windows NT 10.0; Win64; x64", '"Windows"'),
    "macos": ("Macintosh; Intel Mac OS X 10_15_7", '"macOS"'),
    "linux": ("X11; Linux x86_64", '"Linux"'),
    "android": ("Linux; Android 10; K", '"Android"'),
}


def chrome_ua(major, platform="windows"):
    os_token, _ = CHROME_OS[platform]
    mobile = "Mobile " if platform == "android" else ""
    return (f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 {mobile}Safari/537.36")


def chrome_brands(major):
    return f'"Google Chrome";v="{major}", "Not?A_Brand";v="8", "Chromium";v="{major}"'


def chrome(major, platform, kind, base_url, referer=None):
    _, ch_platform = CHROME_OS[platform]
    h = [("Connection", "keep-alive")]
    if kind == "post":
        h.append(("Cache-Control", "max-age=0"))
    h += [("sec-ch-ua", chrome_brands(major)),
          ("sec-ch-ua-mobile", "?1" if platform == "android" else "?0"),
          ("sec-ch-ua-platform", ch_platform)]
    if kind == "post":
        h += [("Origin", base_url), ("Content-Type", "application/x-www-form-urlencoded")]
    h += [("Upgrade-Insecure-Requests", "1"), ("User-Agent", chrome_ua(major, platform)),
          ("Accept", CHROME_ACCEPT),
          ("Sec-Fetch-Site", "none" if kind == "typed" else "same-origin"),
          ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-User", "?1"), ("Sec-Fetch-Dest", "document")]
    if referer:
        h.append(("Referer", referer))
    h += [("Accept-Encoding", "gzip, deflate, br, zstd"), ("Accept-Language", "en-US,en;q=0.9")]
    return h


def firefox(major, kind, base_url, referer=None):
    h = [("User-Agent", f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"),
         ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
         ("Accept-Language", "en-US,en;q=0.5"), ("Accept-Encoding", "gzip, deflate, br, zstd")]
    if kind == "post":
        h += [("Content-Type", "application/x-www-form-urlencoded"), ("Origin", base_url)]
    h.append(("Connection", "keep-alive"))
    if referer:
        h.append(("Referer", referer))
    h += [("Upgrade-Insecure-Requests", "1"), ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-Mode", "navigate"),
          ("Sec-Fetch-Site", "none" if kind == "typed" else "same-origin"), ("Sec-Fetch-User", "?1"),
          ("Priority", "u=0, i")]
    return h


def safari(platform, kind, base_url, referer=None):
    if platform == "ios":
        ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1")
    else:
        ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/26.0 Safari/605.1.15")
    h = [("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
         ("Sec-Fetch-Site", "none" if kind == "typed" else "same-origin"),
         ("Sec-Fetch-Dest", "document"), ("Accept-Language", "en-US,en;q=0.9"),
         ("Sec-Fetch-Mode", "navigate")]
    if kind == "post":
        h += [("Content-Type", "application/x-www-form-urlencoded"), ("Origin", base_url)]
    h.append(("User-Agent", ua))
    if referer:
        h.append(("Referer", referer))
    h += [("Accept-Encoding", "gzip, deflate, br"), ("Connection", "keep-alive")]
    return h


def headers_for(browser, kind, base_url, referer=None):
    """browser: ("chrome", major, platform) | ("firefox", major) | ("safari", platform)"""
    family = browser[0]
    if family == "chrome":
        return chrome(browser[1], browser[2], kind, base_url, referer)
    if family == "firefox":
        return firefox(browser[1], kind, base_url, referer)
    return safari(browser[1], kind, base_url, referer)
