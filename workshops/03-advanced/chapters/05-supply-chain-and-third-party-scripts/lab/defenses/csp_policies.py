"""
csp_policies.py — the three Content-Security-Policy strings this chapter uses,
in one readable place. demo_site/app.py builds the same strings from CSP_MODE;
this module is the studied copy, with a tiny helper to print them.

  weak()   the host-allowlist policy of Round 2. It works against a naive
           beacon (connect-src 'self'), but it carries two realistic mistakes:
           'unsafe-inline' (so an injected inline script runs) and a permissive
           img-src (so a pixel can still exfil). Round 3's attack uses both.

  strict() the modern policy of Round 3. No allowlist to bypass: only a script
           carrying the per-response nonce runs, strict-dynamic lets those
           scripts load the code they trust, and the exfil channels are shut.
"""


def weak() -> str:
    return (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https:; "   # 'unsafe-inline' = the hole
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: http: https:; "           # permissive = the exfil pixel
        "connect-src 'self'; "                           # blocks the naive beacon
        "font-src 'self'; "
        "report-uri /csp-report"
    )


def strict(nonce: str, trusted_analytics: str = "") -> str:
    # Most real stores must allow ONE third-party beacon origin in connect-src.
    # That single exception is the gap a poisoned first-party bundle rides in
    # Round 4 — which is why the runtime monitor exists.
    extra = f" {trusted_analytics}" if trusted_analytics else ""
    return (
        f"default-src 'self'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
        f"object-src 'none'; "
        f"base-uri 'none'; "
        f"style-src 'self'; "
        f"img-src 'self' data:{extra}; "
        f"connect-src 'self'{extra}; "
        f"font-src 'self'; "
        f"frame-ancestors 'self'; "
        f"require-trusted-types-for 'script'; "
        f"report-uri /csp-report"
    )


if __name__ == "__main__":
    print("# Round 2 — host-allowlist (report-only first, then enforce):\n")
    print(weak(), "\n")
    print("# Round 3 — nonce + strict-dynamic (nonce is per-response):\n")
    print(strict("<per-response-nonce>"))
