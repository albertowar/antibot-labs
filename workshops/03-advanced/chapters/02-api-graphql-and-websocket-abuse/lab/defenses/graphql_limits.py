"""L2 — GraphQL query limits (Round 2).

Request-count rate limiting is blind to GraphQL: one HTTP request can ask for an
unbounded amount of work. Four cheap, static checks on the query document raise
the floor before a resolver ever runs:

  * **introspection off** — reject any query touching ``__schema`` / ``__type``.
    Introspection is a developer convenience that hands an attacker the entire
    API contract in one request. ``__typename`` stays allowed; Apollo and other
    clients send it on normal operations.
  * **depth limit** — reject queries nested past ``MAX_DEPTH``. This stops the
    circular ``order -> user -> orders -> user`` fan-out.
  * **alias limit** — reject queries with more than ``MAX_ALIASES`` aliases. Alias
    batching ( ``a: product(id:1) b: product(id:2) …`` ) packs many fetches into
    one operation and slips past a per-request limiter.
  * **token limit** — reject absurdly large documents outright.

These mirror Strawberry's built-in ``QueryDepthLimiter``, ``MaxAliasesLimiter`` and
``MaxTokensLimiter`` extensions, which you would use in production. We implement
them by hand here so the mechanism — and, in Round 3, the way a *naive* alias
count is bypassed — is visible rather than hidden in a dependency.

Note the alias counter here does **not** follow fragment spreads. That is the
deliberate weakness Round 3 exploits; see persisted_queries.py for the fix.

False positives: a legitimate first-party app can write a genuinely deep or
alias-heavy query. Set the caps from your real client's largest operation plus
headroom, and prefer the persisted-query allowlist (Round 3) for first-party
traffic so these numeric caps only have to catch unknown callers.
"""

from __future__ import annotations

from graphql import parse
from graphql.language import (
    FieldNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    OperationDefinitionNode,
)
from graphql.language.lexer import Lexer
from graphql.language.source import Source
from graphql.language.token_kind import TokenKind

MAX_DEPTH = 6
MAX_ALIASES = 15
MAX_TOKENS = 1500
BLOCK_POINTS = 60


def _fragments(doc) -> dict:
    return {d.name.value: d for d in doc.definitions
            if d.__class__.__name__ == "FragmentDefinitionNode"}


def depth(selection_set, frags, expand=True) -> int:
    if selection_set is None:
        return 0
    best = 0
    for sel in selection_set.selections:
        if isinstance(sel, FieldNode):
            best = max(best, 1 + depth(sel.selection_set, frags, expand))
        elif isinstance(sel, InlineFragmentNode):
            best = max(best, depth(sel.selection_set, frags, expand))
        elif isinstance(sel, FragmentSpreadNode) and expand:
            frag = frags.get(sel.name.value)
            if frag is not None:
                best = max(best, depth(frag.selection_set, frags, expand))
    return best


def alias_count(selection_set, frags, expand=False) -> int:
    """Count aliases. With expand=False (naive) fragment spreads are not followed."""
    if selection_set is None:
        return 0
    total = 0
    for sel in selection_set.selections:
        if isinstance(sel, FieldNode):
            total += 1 if sel.alias else 0
            total += alias_count(sel.selection_set, frags, expand)
        elif isinstance(sel, InlineFragmentNode):
            total += alias_count(sel.selection_set, frags, expand)
        elif isinstance(sel, FragmentSpreadNode) and expand:
            frag = frags.get(sel.name.value)
            if frag is not None:
                total += alias_count(frag.selection_set, frags, expand)
    return total


def has_introspection(selection_set, frags) -> bool:
    if selection_set is None:
        return False
    for sel in selection_set.selections:
        if isinstance(sel, FieldNode):
            if sel.name.value in ("__schema", "__type"):
                return True
            if has_introspection(sel.selection_set, frags):
                return True
        elif isinstance(sel, InlineFragmentNode):
            if has_introspection(sel.selection_set, frags):
                return True
        elif isinstance(sel, FragmentSpreadNode):
            frag = frags.get(sel.name.value)
            if frag is not None and has_introspection(frag.selection_set, frags):
                return True
    return False


def token_count(query: str) -> int:
    lexer = Lexer(Source(query))
    n = 0
    while True:
        tok = lexer.advance()
        if tok.kind == TokenKind.EOF:
            break
        n += 1
        if n > MAX_TOKENS * 4:
            break
    return n


def score_query(query: str) -> tuple[int, list[str]]:
    """Return (points, reasons). A violation should return a blocking score."""
    # TODO (Round 2): parse the query and enforce the four static limits:
    #   - reject introspection (has_introspection);
    #   - reject depth > MAX_DEPTH (depth, expand=True);
    #   - reject alias_count > MAX_ALIASES  (expand=False — the naive count);
    #   - reject token_count > MAX_TOKENS.
    # Return (BLOCK_POINTS, [reasons]) on any violation, else (0, []).
    # Catch up with: python tools/checkpoint.py --round 2 --catch-up
    return 0, []
