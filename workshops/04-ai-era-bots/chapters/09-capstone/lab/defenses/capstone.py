"""
W4 Ch9 Capstone — the ladder glue: the stack's layers as starter checks (GIVEN)

The capstone's layers are the same modules the W4 chapters built; this module
only adapts them to the gate's Check interface and keeps one session view for
all of them (no train/serve skew between the checkout decision, the rule
engine's card and the scoreboard).

    LADDER[0]   request_headers + egress_rate (W1, request phase, always on)
                + the W2 browser stack (automation, fingerprint coherence,
                  behaviour flow) as shadow=True checks: they report on every
                  checkout and never decide — Round 0's "what would W2 say"
    LADDER[2]   agent_governance at action:checkout (Round 2)
    LADDER[4]   the human-approved rules at action:checkout (Round 4)

Crawl governance (L1) and the deception limits + LLM guard (L3) act on content
RESPONSES (402, maze pages, shaped replies), which a Check cannot express; they
live in demo_site/ext/capstone_store.py and read ctx.level themselves — the
same pattern W4 Ch3 and Ch5 use (and the Decision the contract records for it).

Run the store with LAB_SHADOW=1 to see every layer above the current level in
X-Lab-Shadow: that is Round 0's whole lesson, on the standard mechanism.
"""

import json
import time

from . import agent_behavior, agent_governance, agent_identity, agent_policy, automation
from . import behavior_flow, fingerprint_coherence, mandates, policy_engine, request_checks
from . import risk_engine, rules as rules_mod, signals
from .pipeline import Check, Signal, Verdict

DROP_SKU = "lab-runner-9"
RULE_ENGINE = rules_mod.RuleEngine()


class _Headers:
    """request_checks/httpsig read headers with .get(); Ctx keeps an ordered list."""

    def __init__(self, ctx):
        self._ctx = ctx

    def get(self, name, default=None):
        return self._ctx.header(name, default)

    def __contains__(self, name):
        return self._ctx.header(name) is not None


def request_ctx9(ctx):
    """The dict shape every ported W4 module reads (the old app's request_context)."""
    return {"method": ctx.method, "path": ctx.path, "headers": _Headers(ctx),
            "ua": ctx.ua.raw, "authority": ctx.host, "egress": ctx.ip,
            "egress_kind": egress_kind(ctx), "sid": ctx.session.sid}


def egress_kind(ctx):
    """datacenter / residential, from the simulated edge's pool type via the feeds."""
    from . import netinfo
    kind = netinfo.lookup(ctx.ip)["asn_type"]
    return "datacenter" if kind == "datacenter" else "residential"


def session_state(ctx, page="/checkout"):
    """Telemetry + flow for this session, from the keys the collector ext writes."""
    sid = ctx.session.sid
    r = ctx.redis
    fp = r.get(f"lab:cap:fp:{sid}")
    pages = {}
    for name in r.smembers(f"lab:cap:evpages:{sid}"):
        raw = r.get(f"lab:cap:ev:{sid}:{name}")
        if raw:
            pages[name] = json.loads(raw)
    flow = [json.loads(x) for x in r.lrange(f"lab:cap:flow:{sid}", 0, -1)]
    return {"sid": sid, "page": page, "fp": json.loads(fp) if fp else None,
            "fp_hash": r.get(f"lab:cap:fph:{sid}"), "events": pages.get(page), "pages": pages,
            "flow": flow, "now_ms": int(time.time() * 1000), "http_ua": ctx.ua.raw}


def principal_identity(ctx):
    """Who is behind this request: human, declared agent, or (L2+) verified agent."""
    identity = agent_identity.verify(ctx)
    principal = agent_policy.classify(_Headers(ctx))
    if ctx.level >= 2 and identity["status"] == "verified":
        principal = {"kind": "verified_agent", "operator": identity["operator"],
                     "evidence": principal["evidence"] + [f"Web Bot Auth signature by {identity['operator']}"]}
    return principal, identity


def user_state(ctx):
    from demo_site.models import Order
    u = ctx.user
    age_s = max(0.0, time.time() - u.created_at.timestamp()) if u.created_at else 0.0
    prior = Order.query.filter(Order.user_id == u.id).filter(
        ~Order.items.any(sku=DROP_SKU)).count()
    return {"id": u.id, "email": u.email, "address": "", "account_age_days": age_s / 86400,
            "prior_orders": prior}


def _units(ctx, sku, user_id, dkey):
    from demo_site.models import Order, OrderItem
    if sku != DROP_SKU:
        return 0, 0
    account = Order.query.filter(Order.user_id == user_id, Order.items.any(sku=DROP_SKU)).count()
    device = int(ctx.redis.get(f"lab:cap:dev:{dkey}") or 0)
    return account, device


def checkout_ctx9(ctx, sess, ustate, principal):
    """The orchestration dict agent_governance.evaluate reads (the old app's _checkout ctx)."""
    from datetime import datetime, timedelta, timezone
    from demo_site.models import Order
    body = ctx.json if isinstance(ctx.json, dict) else {}
    sku = _cart_sku(ctx) or body.get("sku") or ""
    mandate_id = body.get("mandate") or ctx.header("X-Agent-Mandate")
    mandate = mandates.get(mandate_id) if mandate_id else None
    dkey = f"fp:{sess['fp_hash'] or 'none'}"
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    account_units, device_units = _units(ctx, sku, ustate["id"], dkey)
    return {
        "sku": sku, "mandate": mandate, "now": now, "device_key": dkey,
        "orders_last_hour": Order.query.filter(Order.user_id == ustate["id"],
                                               Order.created_at >= hour_ago.replace(tzinfo=None)).count(),
        "device_units": device_units, "account_units": account_units,
        # the starter's clearance IS the solved-challenge state: the downgrade rule
        # absorbs the challenge verdict on the retry, so these stay False here and the
        # resumed flag (ctx.resumed) is what skips double-counting
        "step_up_confirmed": False, "challenge_solved": False,
    }


def _cart_sku(ctx):
    for k, qty in ctx.redis.hgetall(ctx.session.ns("cart") + "items").items():
        if int(qty) > 0:
            return k.partition("|")[0]
    return None


def signal_row(ctx, sess, ustate, principal):
    fp_accounts = signals.fp_reuse_count(ctx.redis, sess["fp_hash"], ustate["id"]) \
        if ctx.user else 0
    row = signals.derive(sess, ustate, principal, {"score": 0, "reasons": []},
                         egress_kind(ctx), fp_accounts)
    return row, fp_accounts


# --- LADDER[0]: W1 request checks -----------------------------------------------------------------

def _request_headers(ctx):
    points, reasons = request_checks.score_headers(request_ctx9(ctx))
    return [Signal("L0", "headers", points, "; ".join(reasons)[:160])] if points else None


def _egress_rate(ctx):
    points, reasons = request_checks.score_rate(request_ctx9(ctx), ctx.redis)
    return [Signal("L0", "rate", points, "; ".join(reasons)[:160])] if points else None


# --- LADDER[0], shadow: what the W2 browser stack would say about a checkout ----------------------

def _w2_shadow(ctx):
    sess = session_state(ctx)
    points, reasons = risk_engine.w2_shadow(sess)
    return [Signal("W2", "stack", points, "; ".join(reasons)[:160])] if points else None


# --- LADDER[2]: agent governance at the checkout (Round 2) ---------------------------------------

def _agent_governance(ctx):
    if ctx.user is None:
        return None                              # the route refuses unauthenticated checkouts itself
    principal, identity = principal_identity(ctx)
    sess = session_state(ctx)
    ustate = user_state(ctx)
    row, fp_accounts = signal_row(ctx, sess, ustate, principal)
    ctx9 = checkout_ctx9(ctx, sess, ustate, principal)
    if ctx.resumed:
        # The retry after a clearance: clear ONLY what was actually solved, by type. A solved
        # proof of work must not also satisfy the human-confirmation step-up — that is how an
        # unattended farm that can crunch a PoW still fails at the emailed code (contract 1.7).
        ctx9["challenge_solved"] = ctx.cleared("pow") or ctx.cleared("captcha_image")
        ctx9["step_up_confirmed"] = ctx.cleared("confirm_code")
    pol = policy_engine.load_policy()
    (points, reasons), extra = agent_governance.evaluate(pol, row, principal, identity, ustate, ctx9)
    ctx.attrs["cap_extra"] = extra
    ctx.attrs["cap_row"] = row
    ctx.attrs["cap_principal"] = principal
    ctx.note(principal=principal["kind"], operator=principal.get("operator"),
             client=row["client"], cap_signals=",".join(row["signals"]))
    if extra.get("mandate_ok"):
        ctx.note(mandate=extra["mandate_ok"])
    # Carry the governance points on the signals: challenge is not a hard action, so the gate
    # re-derives it from the summed score, not from the Verdict's action. Put the full weight
    # on the first reason; a Verdict with zero-point signals would decide "allow" (contract 1.7).
    sigs = tuple(Signal("L2", "governance", points if i == 0 else 0, r[:160])
                 for i, r in enumerate(reasons[:4])) or (Signal("L2", "governance", points, "policy"),)
    if points >= 60:
        return Verdict("block", 100, sigs)
    if points >= 30:
        kind = extra.get("challenge") or ("confirm_code" if extra.get("step_up") else None)
        ctx.note(challenge_kind=kind, non_visual=bool(kind) and kind != "captcha_image")
        return Verdict("challenge", points, sigs, challenge=kind or pol.get("challenge_type", "pow"))
    return list(sigs) or None


# --- LADDER[4]: the human-approved rules (Round 4) ------------------------------------------------

def _approved_rules(ctx):
    if ctx.user is None:
        return None
    principal, _identity = principal_identity(ctx)
    sess = session_state(ctx)
    ustate = user_state(ctx)
    row, fp_accounts = signal_row(ctx, sess, ustate, principal)
    ctx9 = checkout_ctx9(ctx, sess, ustate, principal)
    card = risk_engine.session_card(row, ustate, ctx9, ctx.ua.raw, egress_kind(ctx), fp_accounts)
    hit, _shadow, ms = RULE_ENGINE.evaluate(card)
    ctx.note(rules_ms=round(ms, 3))
    if hit:
        conds = " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in hit["when"]["all"])
        ctx.note(rule_id=hit.get("id"))
        return Verdict("block", 100, (Signal("L4", "approved_rule", 100, f"{hit.get('id')}: {conds}"[:160]),))
    return None


# The whole W1+W2 baseline runs in shadow: it is the "what would the earlier stack say"
# telemetry Round 0 reads and the feature that feeds would_block (the deception limit) and
# the checkout risk row. It never enforces on its own — content is governed by the crawl
# gate (L1), the checkout by agent governance (L2) and the rules (L4). This matches the
# old capstone (its request score was advisory) and W4 Ch5 (no W1 check in its ladder).
REQUEST_HEADERS = Check("request_headers", _request_headers, shadow=True)
EGRESS_RATE = Check("egress_rate", _egress_rate, shadow=True)
W2_SHADOW = Check("w2_stack", _w2_shadow, phases=("action:checkout", "action:drop_buy"), shadow=True)
AGENT_GOVERNANCE = Check("agent_governance", _agent_governance, phases=("action:checkout", "action:drop_buy"))
APPROVED_RULES = Check("approved_rules", _approved_rules, phases=("action:checkout", "action:drop_buy"))
