"""
The ladder for W3 Ch2: which checks run at which DEFENSE_LEVEL. (YOUR FILE; the round solutions leave it alone.)

    level  round  adds                                      module                      where
    -----  -----  ----------------------------------------  --------------------------  ------------------------------
      0    --     nothing: the attacker's playground
      1    1      cost-aware REST rate limiting             rate_cost                   /api/products*, /api/v2/*
      2    2      GraphQL: introspection off, depth/alias   graphql_limits              POST /graphql, phase request
      3    3      persisted queries + fragment-aware cost   persisted_queries           POST /graphql, phase request
      4    4      WebSocket: Origin, auth, message rate     ws_guard                    /ws/drop handshake + every frame
      5    5      HMAC request signing + token binding      request_signing,            the two protected /api/v2 reads
                                                            token_binding               (response_deception serves the poison)

Level k is enforced when k <= DEFENSE_LEVEL. Run with LAB_SHADOW=1 and the levels above the current one still
run, logged in X-Lab-Shadow and the decision log but never enforced: see what a layer WOULD do before it can
hurt anyone. The stubs for Rounds 1-5 return nothing until you fill them in; the wiring is done.
"""

from . import graphql_limits, persisted_queries, rate_cost, request_signing, token_binding, ws_guard

LADDER = {
    0: [],
    1: [rate_cost.CHECK],
    2: [graphql_limits.CHECK],
    3: [persisted_queries.CHECK],
    4: [ws_guard.CHECK],
    5: [request_signing.CHECK, token_binding.CHECK],
}
