"""
The operator's view of one request: calendar, overrides, exemptions

demo_site/ext/ops.py runs `begin(ctx)` as an enricher, before any check. It resolves, once per
request:

    week, clock    the lab calendar (tools/weeks.py replays five weeks in minutes and stamps each
                   request with `Lab-Week` / `Lab-Clock`; the store's edge drops every `X-Lab-*`
                   header but the three it documents, so the calendar uses its own names). They go
                   to the decision log and the containment TTL, and nowhere else
    cfg            data/ops_config.json with expired overrides removed (config.effective)
    weights        policy.WEIGHTS with the operator's overrides on top: what `sensors.emit` scores with
    challenge_at / block_at
                   the ladder's lines, with overrides on top: what `policy.decide` uses
    known_good     the request carries the monitors' token (allowlist.py)

Checks read `state(ctx)`; so does `policy.decide`, which receives no ctx from the pipeline and
finds it through flask.g.ctx. Nothing here decides anything.
"""

from . import allowlist, config, policy


def begin(ctx, week=0, clock=0):
    cfg = config.effective(clock or None)
    known_good = allowlist.is_known_good(ctx)
    ctx.attrs["ops"] = {
        "week": week, "clock": clock, "cfg": cfg, "known_good": known_good,
        "weights": {**policy.WEIGHTS, **cfg.get("weights", {})},
        "challenge_at": policy.CHALLENGE_AT if cfg.get("challenge_at") is None else cfg["challenge_at"],
        "block_at": policy.BLOCK_AT if cfg.get("block_at") is None else cfg["block_at"],
    }
    ctx.note(week=week, clock=clock, known_good=known_good,
             overrides=bool(cfg.get("weights") or cfg.get("block_at") or cfg.get("challenge_at")
                            or cfg.get("campaign") or cfg.get("stepup_asn")))


def state(ctx):
    """The request's operational state (shipped policy if the enricher did not run)."""
    return ctx.attrs.get("ops") or {
        "week": 0, "clock": 0, "cfg": dict(config.DEFAULTS), "known_good": False,
        "weights": dict(policy.WEIGHTS), "challenge_at": policy.CHALLENGE_AT, "block_at": policy.BLOCK_AT}
