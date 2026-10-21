"""
Level 5 (Round 1): API hardening. GraphQL cost, token binding, REST velocity (W3 Ch2).

The browser stack (levels 1 to 4) watches pages, fingerprints and behaviour. An API client has almost none of that
surface: no canvas, no mouse, often no HTML at all. So the API needs its own controls, and they are about *shape
and rate*, not about what the client looks like:

    introspection   a public API that answers __schema hands an attacker the whole map in one request. Turn it
                    off in production.
    cost / depth    one POST can alias `product(...)` two hundred times, or ask for the whole catalogue in one
                    `products` field, or nest selections to recurse. Reject by a computed budget *before*
                    resolving (defenses/graphql_cost.py).
    token binding   the REST catalogue needs a bearer token bound to the client's JA4 (defenses/api_token.py);
                    a call with no token, or a token replayed from another TLS stack, is refused.
    REST velocity   paginated scraping walks /api/v1/products fast. Count per fingerprint cluster (JA4 a+b), not
                    per address: a residential proxy pool rotates addresses, and a carrier NAT shares one.

The check runs in the `request` phase and only looks at POST /graphql and GET /api/v1/*; every other request is
none of its business. A violation is 60 points, a block (defenses/policy.py), and the reason goes to the decision
log and `X-Lab-Signals` (a real API would not say which rule fired).

What it does not do: none of this identifies a *client*. A legitimate mobile app and a scraper both speak JSON
over HTTP. What separates them here is the bound token and the request shape, which is why every checkpoint
measures the legitimate mobile and partner clients right next to the scraper.
"""

from . import api_token, graphql_cost, ja4, policy
from .pipeline import Check, Signal

# --- TODO (Round 1): tune the GraphQL budget and introspection ---------------------------------------
# Run `python attacks/round1_api.py` at level 4 (everything gets through), then edit these and run it at
# level 5. The reference solution is in solutions/round1/defenses/api_hardening.py.
#   - INTROSPECTION_ENABLED: a public storefront API has no reason to answer __schema. Turn it off.
#   - GRAPHQL_MAX_COST: the legitimate mobile client asks for a page of 24 products (cost 24); the batch
#     scraper asks for the whole catalogue (aliases, or one `products` field: cost 120 and up). Put the
#     ceiling above the honest page and below the scrape.
#   - GRAPHQL_MAX_DEPTH: honest queries are two or three deep; a recursive abuse query is much deeper.
INTROSPECTION_ENABLED = False     # SOLUTION (Round 1): a public storefront API should not answer __schema
GRAPHQL_MAX_COST = 50              # SOLUTION (Round 1): above the 24-item honest page, below a catalogue scrape (120)
GRAPHQL_MAX_DEPTH = 6              # SOLUTION (Round 1): honest queries are two or three deep
# -----------------------------------------------------------------------------------------------------


def score_graphql(analysis):
    """Signals for one analyzed GraphQL body. Any signal is a block: the query is refused before it resolves."""
    out = []
    if analysis.get("introspection") and not INTROSPECTION_ENABLED:
        out.append(Signal("api_hardening", "introspection", policy.API_POINTS, "GraphQL introspection is disabled on this API"))
    if analysis.get("cost", 0) > GRAPHQL_MAX_COST:
        out.append(Signal("api_hardening", "query_cost", policy.API_POINTS,
                          f"GraphQL query cost {analysis['cost']} over budget {GRAPHQL_MAX_COST} "
                          f"({analysis.get('batch', 1)} operation(s))"))
    if analysis.get("depth", 0) > GRAPHQL_MAX_DEPTH:
        out.append(Signal("api_hardening", "query_depth", policy.API_POINTS,
                          f"GraphQL query depth {analysis['depth']} over limit {GRAPHQL_MAX_DEPTH}"))
    return out


def score_token(token_state):
    """Signals for the bearer token on a REST call. token_state is (ok, claims | reason) from api_token.verify."""
    ok, why = token_state
    if ok:
        return []
    name = "token_replayed" if "mismatch" in why else "no_token" if why == "no API token" else "bad_token"
    return [Signal("api_hardening", name, policy.API_POINTS, why)]


def rest_velocity(ctx):
    """Count catalogue pages per fingerprint cluster in a sliding minute (a fixed window, one INCR)."""
    cluster = ja4.fingerprint(ctx).ja4_ab or "no-ja4"
    key = f"lab:api:rest:{cluster}"
    n = ctx.redis.incr(key)
    if n == 1:
        ctx.redis.expire(key, policy.REST_WINDOW_S)
    ctx.note(rest_pages=n)
    if n > policy.REST_MAX_PAGES:
        return [Signal("api_hardening", "rest_velocity", policy.API_POINTS,
                       f"REST catalogue paged {n}x in {policy.REST_WINDOW_S}s per fingerprint cluster "
                       f"(> {policy.REST_MAX_PAGES}): scraping")]
    return []


def _check(ctx):
    if ctx.path == "/graphql" and ctx.method == "POST":
        analysis = graphql_cost.analyze_body(ctx.json)
        ctx.note(gql_cost=analysis["cost"], gql_depth=analysis["depth"], gql_batch=analysis["batch"])
        return score_graphql(analysis)
    if ctx.path.startswith("/api/v1/"):
        state = ctx.attrs.get("api_token", (False, "no API token"))
        signals = score_token(state)
        if not signals:                       # a valid token is counted; an invalid one is refused already
            signals = rest_velocity(ctx)
        return signals
    return None


CHECK = Check("api_hardening", _check, phases=("request",))


if __name__ == "__main__":
    normal = graphql_cost.analyze_body({"query": "{ products(limit: 24) { sku name price } }"})
    batch = graphql_cost.analyze_body([{"query": "{ " + " ".join(f'p{i}: product(sku:"s{i}"){{name}}' for i in range(200)) + " }"}])
    intro = graphql_cost.analyze_body({"query": "{ __schema { types { name } } }"})
    # With the starter (loose) configuration nothing is blocked:
    assert not score_graphql(normal)
    print("starter config: batch signals", len(score_graphql(batch)), "| introspection signals", len(score_graphql(intro)))
    # Simulate the reference solution:
    globals().update(INTROSPECTION_ENABLED=False, GRAPHQL_MAX_COST=50, GRAPHQL_MAX_DEPTH=6)
    assert not score_graphql(normal), "the honest page must pass"
    assert score_graphql(batch), "the batch scrape must be refused"
    assert score_graphql(intro), "introspection must be refused"
    print("api_hardening self-test OK (the solution's numbers refuse the batch and introspection, and pass the honest page)")
