"""
Capstone — a deliberately small GraphQL surface (W3 Ch2)

Real GraphQL servers (Ariadne, Strawberry, graphql-core) are heavier than a
teaching lab needs, and they hide the one thing this round is about: a single
POST can ask for an unbounded amount of work. So this is a minimal,
dependency-free resolver over the store's product catalog, plus the two things
every GraphQL attack starts with — introspection and aliased batching.

What it exposes:
    products(limit, offset) -> [Product]      the catalog, paginated
    product(sku: "...")     -> Product         one item
    __schema / __type       -> introspection   the full type map in one request

The defense (defenses/api_hardening.py, L5) decides whether a query is allowed
*before* it runs, from two numbers this module computes without resolving:

    depth : maximum selection-set nesting  (a recursive query inflates this)
    cost  : number of root-level field selections (an aliased batch inflates
            this — `p0: product(...) p1: product(...) ...` is one HTTP request
            but N resolver calls)

`analyze()` is pure and unit-tested in __main__; keep it that way so the L5
policy can reason about a query it has not run.
"""

import re

CATALOG_FIELDS = {"sku", "name", "price", "drop"}
INTROSPECTION_TOKENS = ("__schema", "__type", "__typename")
_SKU = re.compile(r'sku\s*:\s*"([^"]+)"')
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _strip_strings(query):
    """Remove string literals so braces/parens inside them don't skew the counts."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', query)


def analyze(query):
    """Return {depth, cost, introspection, root_fields} for a single query string."""
    q = _strip_strings(query or "")
    depth = cur = 0
    cost = 0
    root_fields = []
    i = 0
    # Walk the selection sets. A field is counted at depth 1 (a root field);
    # every '{' increases depth, every '}' decreases it.
    pending_ident = None
    for tok in re.finditer(r'[{}]|[A-Za-z_][A-Za-z0-9_]*', q):
        t = tok.group()
        if t == '{':
            if cur == 1 and pending_ident:
                root_fields.append(pending_ident)
            cur += 1
            depth = max(depth, cur)
            pending_ident = None
        elif t == '}':
            cur = max(0, cur - 1)
            pending_ident = None
        else:
            # an identifier directly inside the operation's root set is a root field
            if cur == 1:
                pending_ident = t
    cost = max(len(root_fields), q.count('('))  # aliased batches use product(...) N times
    introspection = any(tok in q for tok in INTROSPECTION_TOKENS)
    return {"depth": depth, "cost": cost, "introspection": introspection, "root_fields": root_fields}


def analyze_body(body):
    """A GraphQL POST body may be one query or a JSON array (batch). Return the worst case."""
    ops = body if isinstance(body, list) else [body]
    worst = {"depth": 0, "cost": 0, "introspection": False, "root_fields": [], "batch": len(ops)}
    for op in ops:
        a = analyze((op or {}).get("query", "")) if isinstance(op, dict) else {"depth": 0, "cost": 0, "introspection": False, "root_fields": []}
        worst["depth"] = max(worst["depth"], a["depth"])
        worst["cost"] += a["cost"]
        worst["introspection"] = worst["introspection"] or a["introspection"]
        worst["root_fields"] += a["root_fields"]
    return worst


# --------------------------------------------------------------------------
# Resolution (only reached once the L5 policy has allowed the query)
# --------------------------------------------------------------------------

SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "products", "args": ["limit", "offset"], "type": "[Product]"},
            {"name": "product", "args": ["sku"], "type": "Product"}]},
        {"kind": "OBJECT", "name": "Product", "fields": [
            {"name": "sku"}, {"name": "name"}, {"name": "price"}, {"name": "drop"}]},
    ],
}


def _product_view(sku, products):
    p = products.get(sku)
    return {"sku": sku, "name": p["name"], "price": p["price"], "drop": p["drop"]} if p else None


def resolve(op, products):
    """Resolve one allowed operation against the in-memory catalog."""
    query = op.get("query", "")
    if any(tok in query for tok in INTROSPECTION_TOKENS):
        return {"data": {"__schema": SCHEMA}}
    data = {}
    skus = _SKU.findall(query)
    if "products" in query and not skus:
        limit_m = re.search(r'limit\s*:\s*(\d+)', query)
        offset_m = re.search(r'offset\s*:\s*(\d+)', query)
        limit = int(limit_m.group(1)) if limit_m else 1000
        offset = int(offset_m.group(1)) if offset_m else 0
        items = [{"sku": s, "name": p["name"], "price": p["price"], "drop": p["drop"]}
                 for s, p in products.items()]
        data["products"] = items[offset:offset + limit]
    for idx, sku in enumerate(skus):
        # aliased batches become product_0, product_1, ... so each result is addressable
        key = f"product_{idx}" if len(skus) > 1 else "product"
        data[key] = _product_view(sku, products)
    return {"data": data}


def resolve_body(body, products):
    if isinstance(body, list):
        return [resolve(op or {}, products) for op in body]
    return resolve(body or {}, products)


if __name__ == '__main__':
    # Self-test: the numbers the L5 policy keys on must be right.
    normal = '{ products(limit: 10) { sku name price } }'
    intro = '{ __schema { types { name fields { name } } } }'
    batch = '{ ' + ' '.join(f'p{i}: product(sku: "s{i}") {{ name price }}' for i in range(50)) + ' }'
    deep = '{ a { b { c { d { e { f { g } } } } } } }'
    a = analyze(normal); assert not a["introspection"] and a["cost"] <= 2, a
    b = analyze(intro); assert b["introspection"], b
    c = analyze(batch); assert c["cost"] >= 50, c
    d = analyze(deep); assert d["depth"] >= 7, d
    print("analyze() self-test OK")
    print("  normal", analyze(normal))
    print("  intro ", {k: analyze(intro)[k] for k in ("depth", "cost", "introspection")})
    print("  batch ", {k: analyze(batch)[k] for k in ("depth", "cost", "introspection")})
    print("  deep  ", {k: analyze(deep)[k] for k in ("depth", "cost", "introspection")})
