"""
W3 Ch2 ext: the GraphQL endpoint, /graphql (the contract reserves the path for this chapter).

    GET  /graphql   what the endpoint is and the limits Round 2 will enforce
    POST /graphql   {"query", "operationName", "variables", "extensions"}, or an array of those (batching)

The request goes through the store's gate like any other: ``gate.before_request`` builds the Ctx, which carries
the parsed JSON body as ``ctx.json``, and the ladder's checks (defenses/graphql_limits.py at level 2,
defenses/persisted_queries.py at level 3) read the query document from there. A refused request never reaches
this module. What lives here is only the execution and one piece of basic hygiene that is on at every level:
an array-batched body is capped at MAX_BATCH operations.

Every answer carries ``extensions.cost``, the resolver-cost counter from gql_schema.py: the number the
chapter's attacks are measured in. Ext modules are not hot-reloaded: restart the store after editing this file.
"""

from flask import Blueprint, jsonify, request

from demo_site.ext.gql_schema import schema

MAX_BATCH = 25          # hygiene on at every level: cap array-batched operations

bp = Blueprint("gql", __name__)


def _defense_limits():
    import importlib
    gl = importlib.import_module("defenses.graphql_limits")
    return {"max_depth": gl.MAX_DEPTH, "max_aliases": gl.MAX_ALIASES, "max_tokens": gl.MAX_TOKENS,
            "max_batch": MAX_BATCH}


def run_operation(op):
    """Execute one operation. Returns the GraphQL answer dict, with the resolver cost in extensions."""
    if not isinstance(op, dict):
        return {"errors": [{"message": "an operation must be a JSON object"}]}
    context = {"cost": 0}
    result = schema.execute_sync(op.get("query") or "", variable_values=op.get("variables"),
                                 operation_name=op.get("operationName"), context_value=context)
    out = {"data": result.data}
    if result.errors:
        out["errors"] = [{"message": str(e.message)} for e in result.errors]
    out["extensions"] = {"cost": context["cost"]}
    return out


@bp.get("/graphql")
def info():
    return jsonify(message="POST a GraphQL operation.", limits=_defense_limits())


@bp.post("/graphql")
def endpoint():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(errors=[{"message": "invalid JSON body"}]), 400
    if isinstance(body, list):
        if len(body) > MAX_BATCH:
            return jsonify(errors=[{"message": f"batch too large (max {MAX_BATCH})"}]), 400
        return jsonify([run_operation(op) for op in body])
    out = run_operation(body)
    return jsonify(out), (200 if out.get("data") is not None else 400)


def init(app):
    app.register_blueprint(bp)
