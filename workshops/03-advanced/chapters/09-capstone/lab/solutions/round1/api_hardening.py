"""
Capstone L5 — API hardening: GraphQL cost, token binding, REST velocity (W3 Ch2)

The browser stack (L0-L4) watches pages, fingerprints and behaviour. An API
client has almost none of that surface: no canvas, no mouse, often no HTML at
all. So the API needs its own controls, and they are about *shape and rate*,
not about what the client looks like:

    introspection   : a public API that answers __schema hands an attacker the
                      whole map in one request. Turn it off in production.
    cost / depth    : one POST can alias `product(...)` a thousand times, or
                      nest selections to recurse. Reject by a computed budget
                      *before* resolving (demo_site/graphql_api.analyze).
    token binding   : API bearer tokens are bound to the client's JA4
                      (demo_site/api_auth); a replayed token fails the check.
    REST velocity   : paginated scraping walks /api/v1/products fast. Count
                      per fingerprint cluster, not per IP (CGNAT, W2 Ch6).

score_api() returns (points, reasons) for the risk engine, and the /graphql and
/api endpoints also *enforce* with the same numbers (a cost overflow is a 403,
not just a score). Keep both in step: never block silently without recording
the reason, and never score without the client learning nothing extra.
"""

# --- TODO (Round 1): tune the GraphQL budget and introspection ---------------
# Run attacks/round1_api.py at L0, then edit these and restart at L5.
#   - INTROSPECTION_ENABLED: a public storefront API has no reason to answer
#     __schema. Turn it off.
#   - GRAPHQL_MAX_COST: the legit mobile client asks for a page of ~24 products
#     (tools/api_traffic.py). The batch scraper asks for the whole catalog in
#     aliases. Put the ceiling above the honest page and below the scrape.
#   - GRAPHQL_MAX_DEPTH: honest queries are 2-3 deep; a recursive abuse query is
#     much deeper.
# The reference solution is in solutions/round1/api_hardening.py.
INTROSPECTION_ENABLED = False   # SOLUTION (Round 1): a public storefront API should not answer __schema
GRAPHQL_MAX_COST = 50           # SOLUTION (Round 1): above the ~24-item honest page, below a catalog scrape
GRAPHQL_MAX_DEPTH = 6            # SOLUTION (Round 1): honest queries are 2-3 deep
# -----------------------------------------------------------------------------

INTROSPECTION_POINTS = 60
COST_POINTS = 60
DEPTH_POINTS = 60
BIND_FAIL_POINTS = 60
REST_WINDOW_S = 60
REST_MAX_PAGES = 40               # pages of the catalog per cluster per minute
REST_VELOCITY_POINTS = 60


def score_graphql(analysis):
    """(points, reasons) for one analyzed GraphQL body. Also the enforcement verdict:
    any points here means the query is refused before it resolves."""
    points, reasons = 0, []
    if analysis.get("introspection") and not INTROSPECTION_ENABLED:
        points += INTROSPECTION_POINTS
        reasons.append("GraphQL introspection is disabled on this API")
    if analysis.get("cost", 0) > GRAPHQL_MAX_COST:
        points += COST_POINTS
        reasons.append(f"GraphQL query cost {analysis['cost']} over budget {GRAPHQL_MAX_COST} "
                       f"(aliased batch across {analysis.get('batch', 1)} operation(s))")
    if analysis.get("depth", 0) > GRAPHQL_MAX_DEPTH:
        points += DEPTH_POINTS
        reasons.append(f"GraphQL query depth {analysis['depth']} over limit {GRAPHQL_MAX_DEPTH}")
    return min(points, 100), reasons


def score_token(bind_ok, why):
    return (0, []) if bind_ok else (BIND_FAIL_POINTS, [why])


def rest_velocity(store, cluster, count=True):
    """Count paginated catalog reads per fingerprint cluster in a sliding minute."""
    key = f"api:rest:{cluster}"
    n = store.incr(key) if count else int(store.get(key) or 0)
    if count:
        store.expire(key, REST_WINDOW_S)
    if n > REST_MAX_PAGES:
        return REST_VELOCITY_POINTS, [f"REST catalog paged {n}x in {REST_WINDOW_S}s per fingerprint "
                                      f"cluster (> {REST_MAX_PAGES}): scraping"]
    return 0, []


if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo_site"))
    from graphql_api import analyze_body
    normal = {"query": '{ products(limit: 24) { sku name price } }'}
    batch = [{"query": '{ ' + ' '.join(f'p{i}: product(sku:"s{i}"){{name}}' for i in range(500)) + ' }'}]
    intro = {"query": '{ __schema { types { name } } }'}
    # With the starter (loose) config nothing is blocked:
    assert score_graphql(analyze_body(normal))[0] == 0
    print("starter config — batch points:", score_graphql(analyze_body(batch))[0],
          "intro points:", score_graphql(analyze_body(intro))[0])
    # Simulate the reference solution:
    globals().update(INTROSPECTION_ENABLED=False, GRAPHQL_MAX_COST=50, GRAPHQL_MAX_DEPTH=6)
    assert score_graphql(analyze_body(normal))[0] == 0, "honest page must pass"
    assert score_graphql(analyze_body(batch))[0] >= 60, "batch scrape must block"
    assert score_graphql(analyze_body(intro))[0] >= 40, "introspection must flag"
    print("api_hardening self-test OK (solution config blocks batch + introspection, passes the honest page)")
