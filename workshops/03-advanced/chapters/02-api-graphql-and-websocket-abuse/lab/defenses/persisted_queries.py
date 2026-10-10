"""L3 — persisted queries / trusted documents, and fragment-aware cost (Round 3).

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

from graphql_limits import _fragments, alias_count, depth

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
ALLOWLIST_PATH = os.path.join(DATA, "persisted_queries.json")

MAX_DEPTH = 6
MAX_ALIASES = 15
BLOCK_POINTS = 60

_allow_cache: set[str] | None = None


def normalise(query: str) -> str:
    """Collapse whitespace so formatting never changes a trusted document's hash."""
    return " ".join(query.split())


def query_hash(query: str) -> str:
    return hashlib.sha256(normalise(query).encode()).hexdigest()


def load_allowlist() -> set[str]:
    global _allow_cache
    if _allow_cache is None:
        try:
            with open(ALLOWLIST_PATH) as fh:
                data = json.load(fh)
            _allow_cache = {query_hash(q) for q in data.values()}
        except FileNotFoundError:
            _allow_cache = set()
    return _allow_cache


def score_query(query: str, provided_hash: str | None = None) -> tuple[int, list[str]]:
    """Return (points, reasons) for the persisted-query + fragment-aware layer."""
    # TODO (Round 3): enforce the trusted-documents allowlist, then measure
    # amplification *through* fragment spreads:
    #   - reject any query whose query_hash(query) is not in load_allowlist();
    #   - as defence in depth, reject alias_count/depth (expand=True) over the caps.
    # Return (BLOCK_POINTS, [reasons]) on any violation, else (0, []).
    # Catch up with: python tools/checkpoint.py --round 3 --catch-up
    return 0, []
