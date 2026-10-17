"""
The ladder for W3 Ch1: which checks run at which DEFENSE_LEVEL. (YOUR FILE; the round solutions leave it alone.)

    level  round  adds                                     module                       where
    -----  -----  ---------------------------------------  ---------------------------  -----------------
      0    --     app shape, rate, a soft TLS tell         request_checks.app_shape     every /api/mobile/ request
      1    1      nothing on the server: pinning is        pinned_client.py             in the app
                  client-side, so Round 1 is level 1
      2    2      a valid provider verdict                 attestation.attestation      the buy
      3    3      bound to this request, fresh, single-use request_signing             the buy
      4    4      integrity + device / address velocity    device_verdict               the buy
      5    5      the session is bound to a device key     session_binding              the buy and the orders read

Level k is enforced when k <= DEFENSE_LEVEL. Run with LAB_SHADOW=1 and the levels above the current one still
run, logged in X-Lab-Shadow and the decision log but never enforced: see what a layer WOULD do before it can
hurt anyone. The stubs for Rounds 2-5 return nothing until you fill them in; the wiring is done.
"""

from . import attestation, device_verdict, request_checks, request_signing, session_binding

LADDER = {
    0: [request_checks.CHECK],
    1: [],
    2: [attestation.CHECK],
    3: [request_signing.CHECK],
    4: [device_verdict.CHECK],
    5: [session_binding.CHECK],
}
