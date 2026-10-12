"""
Chapter 2 — Round 1 defense: the JavaScript cookie gate (Section 2.1)

The oldest JS challenge there is. The interstitial page runs a few lines of
inline JavaScript that compute a value and store it in a cookie, then reloads.
Clients that never execute JavaScript never get the cookie.

What it catches: every raw HTTP client that doesn't parse and run the page's
JavaScript (requests, httpx, curl, Scrapy without a renderer).

Why it falls: the "secret" is in the page. The value is the same for every
visitor and every day, so one person reads three lines once and every bot
gets a hard-coded cookie. That's Round 1's attack.

Who it hurts: everyone with JavaScript off. That includes NoScript users,
Tor Browser on "Safest", some corporate lockdowns, text browsers, and many
crawlers you might want (link previews, feed readers, archivers). Decide
what they get: a no-JS fallback, a CAPTCHA (W1 Ch6), or an allowlist for
verified bots (W4 Ch2). Don't let the gate decide for you.

Cost: one cookie compare. Effectively free.
"""

COOKIE_NAME = "js_ok"

# The page computes this from ["7e1", "c0d", "e"].reverse().join("").
EXPECTED_VALUE = "ec0d7e1"

INLINE_SCRIPT = """
  var k = ["7e1", "c0d", "e"];
  document.cookie = "js_ok=" + k.reverse().join("") + "; path=/; SameSite=Lax";
  location.reload();
"""


def passes(cookies):
    """True if the client carries the cookie the inline script would have set."""
    # TODO (Round 1, optional): make the value different for every visitor. What would the
    # server need to remember, and for how long? (That's Round 2.)
    return cookies.get(COOKIE_NAME) == EXPECTED_VALUE


if __name__ == "__main__":
    print("Inline script served to every visitor:")
    print(INLINE_SCRIPT)
    print("A bot that read it sends:", f"{COOKIE_NAME}={EXPECTED_VALUE}",
          "->", passes({COOKIE_NAME: EXPECTED_VALUE}))
