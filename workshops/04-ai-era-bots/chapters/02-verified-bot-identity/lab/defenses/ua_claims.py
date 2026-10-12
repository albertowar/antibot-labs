"""Layer 0 (ships done): turn a User-Agent into a *claim*, never into a verdict.

A crawler announces who it is in the User-Agent string:

    Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
    Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)

Workshop 1, Chapter 4 parsed these for the opposite purpose (spotting scripts).
Here the token is the *claim* the rest of the gate has to verify. At
DEFENSE_LEVEL=0 the store believes the claim outright, which is how a lot of real
allowlists still work and why Round 1 takes ten minutes.

Matching rules that matter in production:
  * match the bare token, case-sensitively where the operator documents a case
    ("bingbot" is lower case, "Googlebot" is not); version numbers change.
  * the first matching token wins; a UA that mentions two operators is already
    suspicious, but that is a Chapter 1 topic.
"""

from __future__ import annotations

from operators import OPERATORS


def claim(user_agent: str) -> str | None:
    """Return the operator key the UA claims to be, or None for an unclaimed client."""
    ua = user_agent or ""
    for key, op in OPERATORS.items():
        for token in op["ua_tokens"]:
            if token in ua:
                return key
    return None


if __name__ == "__main__":
    for ua in ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 Safari/537.36",
               "Mozilla/5.0 (compatible; GPTBot/1.3; +https://openai.com/gptbot)"):
        print(f"{claim(ua)!s:16} <- {ua}")
