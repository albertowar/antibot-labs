"""
Level 5 helper: what a GraphQL query would COST, computed without running it (W3 Ch2).

Real GraphQL servers (Ariadne, Strawberry, graphql-core) are heavier than a teaching lab needs, and they hide the
one thing this layer is about: a single POST can ask for an unbounded amount of work. So the store's /graphql
endpoint (demo_site/ext/api9.py) is a minimal, dependency-free resolver over the catalogue, and this module is
the part the DEFENSE reads. api_hardening.py decides whether a query is allowed *before* it runs, from three
numbers computed here:

    depth          maximum selection-set nesting (a recursive query inflates it)
    cost           resolver work: `product(sku: ...)` is 1; `products(limit: N)` is N (no limit asks for the whole
                   catalogue: CATALOG_SIZE). An aliased batch `p0: product(...) p1: product(...) ...` is one HTTP
                   request and N resolver calls, and a JSON array of operations adds up the same way.
    introspection  the query asks for __schema or __type

`analyze()` is pure and unit-tested in __main__: `python -m defenses.graphql_cost`.

Where it fails: this is a lexical analysis, not a parse. Fragments, variables and directives can hide a limit from it
(W3 Ch2's Round 3 is exactly that bypass); a production API parses with its GraphQL library, walks the document and
weights every field by what its resolver costs.
"""

import re

CATALOG_SIZE = 120                     # a `products` field with no `limit` returns everything
INTROSPECTION_TOKENS = ("__schema", "__type")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_PRODUCTS_CALL = re.compile(r"\bproducts\s*(\(([^)]*)\))?")
_LIMIT = re.compile(r"limit\s*:\s*(\d+)")
_PRODUCT_CALL = re.compile(r"\bproduct\s*\(")


def _strip_strings(query):
    """Remove string literals so braces and parentheses inside them don't skew the counts."""
    return _STRING.sub('""', query)


def analyze(query):
    """Return {depth, cost, introspection} for one query string."""
    raw = query or ""
    q = _strip_strings(raw)
    depth = cur = 0
    for tok in re.finditer(r"[{}]", q):
        if tok.group() == "{":
            cur += 1
            depth = max(depth, cur)
        else:
            cur = max(0, cur - 1)
    cost = len(_PRODUCT_CALL.findall(q))
    for m in _PRODUCTS_CALL.finditer(q):
        limit = _LIMIT.search(m.group(2) or "")
        cost += int(limit.group(1)) if limit else CATALOG_SIZE
    introspection = any(tok in q for tok in INTROSPECTION_TOKENS)
    return {"depth": depth, "cost": cost, "introspection": introspection}


def analyze_body(body):
    """A GraphQL POST body may be one operation or a JSON array (a batch). Return the worst depth and the summed cost."""
    ops = body if isinstance(body, list) else [body]
    worst = {"depth": 0, "cost": 0, "introspection": False, "batch": len(ops)}
    for op in ops:
        a = analyze(op.get("query", "")) if isinstance(op, dict) and isinstance(op.get("query", ""), str) else \
            {"depth": 0, "cost": 0, "introspection": False}
        worst["depth"] = max(worst["depth"], a["depth"])
        worst["cost"] += a["cost"]
        worst["introspection"] = worst["introspection"] or a["introspection"]
    return worst


if __name__ == "__main__":
    # Self-test: the numbers the level 5 policy keys on must be right.
    page = "{ products(limit: 24) { sku name price } }"
    scrape = "{ products { sku name price } }"
    intro = "{ __schema { types { name fields { name } } } }"
    batch = "{ " + " ".join(f'p{i}: product(sku: "s{i}") {{ name price }}' for i in range(50)) + " }"
    deep = "{ a { b { c { d { e { f { g } } } } } } }"
    assert analyze(page) == {"depth": 2, "cost": 24, "introspection": False}, analyze(page)
    assert analyze(scrape)["cost"] == CATALOG_SIZE, analyze(scrape)
    assert analyze(intro)["introspection"], analyze(intro)
    assert analyze(batch)["cost"] == 50, analyze(batch)
    assert analyze(deep)["depth"] == 7, analyze(deep)
    assert analyze_body([{"query": page}, {"query": page}])["cost"] == 48
    assert analyze_body(None) == {"depth": 0, "cost": 0, "introspection": False, "batch": 1}
    print("graphql_cost self-test OK")
    for name, q in (("honest page", page), ("whole catalogue", scrape), ("batch of 50", batch), ("deep", deep)):
        print(f"  {name:<16} {analyze(q)}")
