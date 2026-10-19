"""
The ladder for Chapter 8 (pre-written: every control ships complete; the operator changes
*state*, not code).

    LADDER[0]  (empty)      the bare store: what `tools/verify.py --smoke` tests
    LADDER[1]  sensors      the eight sensor layers (W1 Ch2-4, Ch8; W2 Ch1-5), scored with the
                            shipped weights plus the operator's overrides
               correlation  four cross-signal questions no single sensor can answer
               campaign     a cluster that fails logins like a stuffing run (off until the
                            operator turns it on: config.campaign)
               model        the W2 Ch7 classifier as one more sensor, in the roles prod / shadow /
                            canary (a no-op until a model holds a role: registry.py)
               containment  a blunt ASN step-up with a TTL (a no-op until the operator sets it)

Every check runs only on the login action (phase action:login: POST /login and POST /api/login).
What changes from round to round is the operational state they read: data/ops_config.json,
data/world_updates.json, models/manifest.json, data/labels.jsonl. DEFENSE_LEVEL is not a round
counter here: 0 is the bare store, 1 is the operated stack, and the checkpoint runs everything at 1.
Start the store for the hand-driven weeks with `DEFENSE_LEVEL=1 python demo_site/app.py`.

Hot reload: edit a file in defenses/ and the next request runs it. State files hot-reload too.
"""

from . import campaign, containment, correlation, model, sensors

LADDER = {
    0: [],
    1: [sensors.CHECK, correlation.CHECK, campaign.CHECK, model.CHECK, containment.CHECK],
}
