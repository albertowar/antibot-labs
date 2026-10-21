"""
W4 Ch11 Capstone — from the live store to the W4 Ch10 signal vocabulary (GIVEN)

W4 Ch10's agent policy (policies/agent_policy.json) was written against an
offline session log whose rows carried a set of named signals and a client
class. This adapter builds that row from what the running store knows about a
checkout, so the same JSON drives the live risk engine:

    signal              from
    agent_ua            agent_policy.classify(): a declared agent token in the User-Agent
    signature_agent     a Signature-Agent header is present (a claim; verification is separate)
    datacenter_asn      egress kind (the lab's RFC 5737 ranges; W1 Ch3 in production)
    no_pointer          telemetry: no pointer clicks at all (keyboard, AT, agents)
    timing_too_regular  server-side flow log: metronome cadence (agent_behavior.features)
    cdp_artifacts       automation globals / webdriver in the fingerprint (W2 Ch1)
    ip_burst            the L0 per-egress rate limit fired
    new_account         account under a day old with no purchase history
    fp_reuse            >= FP_REUSE_ACCOUNTS accounts seen on this fingerprint hash today
    screen_reader_api   the collector saw the accessibility API in use (events.a11y_api)
    headless_gpu        software WebGL renderer (fingerprint_coherence)

client class (what kind of thing is at the keyboard):
    browser            a person in a browser
    local_agent        an agent driving the person's own browser (residential egress)
    cloud_agent        an agent on vendor infrastructure (datacenter egress), declared or not
    assistive_agent    an agent driven through the accessibility API

Nothing here reads X-Lab-* headers. The scoreboard knows the truth; the engine
does not.
"""

from . import agent_behavior
from . import automation
from . import fingerprint_coherence

FP_REUSE_ACCOUNTS = 3
ROBOTIC_POINTS = 20


def fp_reuse_count(store, fp_hash, user_id):
    """How many distinct accounts have checked out on this fingerprint hash today."""
    if not fp_hash:
        return 0
    key = f"fpacct:{fp_hash}"
    store.sadd(key, str(user_id))
    store.expire(key, 86400)
    return store.scard(key)


def derive(sess, ustate, principal, request_decision, egress_kind, fp_accounts):
    events_pages = sess.get("pages") or {}
    feats = agent_behavior.features(sess)
    behavior_points = agent_behavior.score(sess)[0]
    a11y = any(bool(ev.get("a11y_api")) for ev in events_pages.values())
    signals = set()
    evidence = " ".join(principal.get("evidence", []))
    if "User-Agent token" in evidence:
        signals.add("agent_ua")
    if "Signature-Agent" in evidence or principal["kind"] == "verified_agent":
        signals.add("signature_agent")
    if egress_kind == "datacenter":
        signals.add("datacenter_asn")
    if events_pages and feats["pointer_clicks"] == 0:
        signals.add("no_pointer")
    if feats["flow_gaps_cv"] is not None and feats["flow_gaps_cv"] < agent_behavior.CADENCE_CV:
        signals.add("timing_too_regular")
    if sess.get("fp") and automation.score_automation(sess)[0] > 0 and sess.get("events") is not None:
        signals.add("cdp_artifacts")
    if any("requests from" in r for r in request_decision.get("reasons", [])):
        signals.add("ip_burst")
    if ustate["account_age_days"] < 1 and ustate["prior_orders"] == 0:
        signals.add("new_account")
    if fp_accounts >= FP_REUSE_ACCOUNTS:
        signals.add("fp_reuse")
    if a11y:
        signals.add("screen_reader_api")
    if sess.get("fp"):
        _, why = fingerprint_coherence.score_coherence(sess["fp"], sess.get("http_ua"))
        if any("Software WebGL" in r for r in why):
            signals.add("headless_gpu")

    declared = principal["kind"] in ("declared_agent", "verified_agent")
    agent_like = declared or (feats["fills_without_keys"] > 0 and feats["teleport_clicks"] > 0) \
        or feats["overlays"] > 0
    if a11y and (feats["fills_without_keys"] > 0 or declared):
        client = "assistive_agent"
    elif agent_like and egress_kind == "datacenter":
        client = "cloud_agent"
    elif agent_like:
        client = "local_agent"
    else:
        client = "browser"
    return {
        "signals": sorted(signals), "client": client, "declared": declared,
        "robotic": behavior_points >= ROBOTIC_POINTS, "behavior_points": behavior_points,
        "a11y": a11y, "features": feats,
    }
