"""
csp_policies.py: the two Content-Security-Policy strings this chapter uses, and the checks that
send them (demo_site/ext/supply.py puts the result in the response header).

  weak()    Round 2 (level 2): the host-allowlist policy. Deployed Report-Only first, then enforced.
            It works against a naive beacon (connect-src 'self'), but it carries two realistic
            mistakes: 'unsafe-inline' (so an injected inline script runs) and a permissive img-src
            (so a pixel can still carry data out). Round 3's skimmer uses both.

  strict()  Round 3 (level 3): nonce + strict-dynamic. There is no allowlist to bypass: a script runs
            only if it carries the per-response nonce or was loaded by one that does, the exfil
            channels (img-src, connect-src) are shut, and Trusted Types refuses string-to-script sinks.
            It must allow ONE analytics origin in connect-src. That exception is what Round 4's
            poisoned first-party bundle rides.

What CSP cannot do: it limits where code can come from and where data can go, not what trusted code
does with the data it can reach. A script that is allowed to run and an origin that is allowed to
receive are a skimmer's whole kit.

False-positive profile: the policy breaks anything that was relying on what it forbids (inline
handlers, `javascript:` URLs, a tag manager that injects unlisted vendors). That is why Round 2 ships
it Report-Only first: the report stream is the list of what enforcement would break. Cost to run: a
reporting endpoint (it will be noisy, mostly from browser extensions) and an owner for the policy.
"""

from .pipeline import Check

REPORT = "/lab/supply/csp-report"


def weak() -> str:
    return (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https:; "    # 'unsafe-inline' = the hole
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: http: https:; "            # permissive = the exfil pixel
        "connect-src 'self'; "                            # blocks the naive beacon and fetch
        "font-src 'self'; "
        f"report-uri {REPORT}"
    )


def strict(nonce: str, analytics_origin: str = "") -> str:
    # A real store allows one third-party beacon origin in connect-src (its analytics vendor). In the
    # lab that origin is the collector's: the attacker holds a tenant on the shared analytics
    # endpoint, which is why a CSP that allows the origin cannot tell the legitimate call from the skim.
    extra = f" {analytics_origin}" if analytics_origin else ""
    return (
        "default-src 'self'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        f"connect-src 'self'{extra}; "
        "font-src 'self'; "
        "frame-ancestors 'self'; "
        "form-action 'self'; "
        "require-trusted-types-for 'script'; "
        f"report-uri {REPORT}"
    )


def _weak(page):
    page.csp = weak()


def _strict(page):
    page.csp = strict(page.nonce, page.analytics_origin)
    page.nonce_scripts = True


WEAK = Check("csp_allowlist", _weak, phases=("page",))
STRICT = Check("csp_strict", _strict, phases=("page",))


if __name__ == "__main__":
    print("# Round 2 (level 2): host-allowlist, Report-Only first and then enforced:\n")
    print(weak(), "\n")
    print("# Round 3 (level 3): nonce + strict-dynamic (the nonce is per response):\n")
    print(strict("<per-response-nonce>", "<analytics-origin>"))
