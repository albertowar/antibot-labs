"""Round 3 (level 3) - persisted queries / trusted documents, and fragment-aware cost.

Round 2's alias limiter counts aliases without following fragment spreads. An
attacker defines one small fragment with a handful of aliased fields and spreads
it many times, or nests spreads, so the *expanded* alias count is huge while the
*surface* count the limiter sees stays tiny. This is not hypothetical: it is the
shape of CVE-2026-47707, an alias-amplification bypass in Strawberry's
MaxAliasesLimiter, where the limiter did not account for how many times a fragment
is resolved. The fix in that CVE was to count through fragments; the fix here is
the same idea, plus the stronger control below.

Two layers:

  * **Fragment-aware counting** — expand fragment spreads before counting aliases
    and depth, so amplification is measured, not hidden. Use this if you must
    accept arbitrary queries from third parties.
  * **Persisted-query allowlist (trusted documents)** — for first-party clients,
    only execute operations approved at build time, identified by the SHA-256 of
    the normalised query text. An operation the client never shipped — including
    every introspection or amplification query an attacker can write — is simply
    not on the list and is rejected before parsing cost matters. This is the
    strongest GraphQL control and the one to reach for first for your own apps.

Note: automatic persisted queries (APQ) that *register on first use* give you the
performance win (small payloads, GET-cacheable) but **no** security, because the
server accepts whatever the client first sends. Security comes only from a strict,
build-time allowlist, which is what this module enforces.

How the gate sees it: like Round 2, this check runs in the ``request`` phase on ``POST /graphql`` and reads the
operations from ``ctx.json``. ``score_query`` is yours; ``_check`` ships done.

False positives: an allowlist can only cover clients whose operations you know
ahead of time. A public GraphQL API with third-party consumers cannot use it;
there you fall back to fragment-aware depth/alias/cost limits and accept the
looser guarantee. Shipping a new first-party client version means regenerating
the allowlist, so it belongs in your build pipeline, not hand-maintained.
"""

from __future__ import annotations

import hashlib
import json
import os

from graphql import parse

from . import graphql_limits as limits
from .pipeline import Check

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
ALLOWLIST_PATH = os.path.join(DATA, "persisted_queries.json")

MAX_DEPTH = 6
MAX_ALIASES = 15
BLOCK_POINTS = 80         # policy blocks at >= 75

_allow_cache: set[str] | None = None


def normalise(query: str) -> str:
    """Collapse whitespace so formatting never changes a trusted document's hash."""
    return " ".join(query.split())


def query_hash(query: str) -> str:
    return hashlib.sha256(normalise(query).encode()).hexdigest()


def load_allowlist() -> set[str]:
    """The hashes of the trusted documents the first-party client ships (data/persisted_queries.json)."""
    global _allow_cache
    if _allow_cache is None:
        try:
            with open(ALLOWLIST_PATH) as fh:
                data = json.load(fh)
            _allow_cache = {query_hash(q) for q in data.values()}
        except FileNotFoundError:
            _allow_cache = set()
    return _allow_cache


def score_query(query: str) -> tuple[int, list[str]]:
    """Return (points, reasons) for the persisted-query + fragment-aware layer."""
    # >>> SOLUTION round3 (allowlist + fragment-aware counting)
    if query_hash(query) not in load_allowlist():   # hash the text we were sent, never a hash the client claims
        return BLOCK_POINTS, ["not allowlisted: query is not a trusted document"]
    # Defence in depth: measure amplification even for an allowlisted document, counting *through*
    # fragment spreads (the bypass Round 2's naive count missed).
    try:
        doc = parse(query)
    except Exception as exc:
        return BLOCK_POINTS, [f"unparseable: {exc}"]
    frags = limits._fragments(doc)
    for defn in doc.definitions:
        if defn.__class__.__name__ != "OperationDefinitionNode":
            continue
        a = limits.alias_count(defn.selection_set, frags, expand=True)
        if a > MAX_ALIASES:
            return BLOCK_POINTS, [f"alias amplification: {a} aliases after fragment expansion (cap {MAX_ALIASES})"]
        d = limits.depth(defn.selection_set, frags, expand=True)
        if d > MAX_DEPTH:
            return BLOCK_POINTS, [f"too deep after fragment expansion: depth {d} (cap {MAX_DEPTH})"]
    return 0, []
    # <<< SOLUTION round3


def _check(ctx):
    found = []
    for query, _ext in limits.operations(ctx):
        points, reasons = score_query(query)
        if points:
            found.append((points, reasons))
    if not found:
        return None
    points = max(p for p, _ in found)
    reasons = [r for _, rs in found for r in rs]
    ctx.note(graphql_reasons=reasons)
    return limits.signals_for("persisted_queries", points, reasons)


CHECK = Check("persisted_queries", _check, phases=("request",))
