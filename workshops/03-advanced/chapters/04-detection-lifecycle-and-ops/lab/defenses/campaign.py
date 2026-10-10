"""
Campaign layer, inherited from W2 Ch8 (run when config.campaign is on)

Round 3's bot makes every *session* look human: fresh fingerprint, fresh
trace, fresh IP. What it cannot hide is the *campaign*. A credential-stuffing
run fails almost every login, because most of the combo list does not match
your users. Real people fail roughly one login in ten.

So we stop judging requests and judge clusters. The cluster key is what the
attacker's tooling holds constant while it rotates everything else:

    JA4 (its TLS stack)  |  device family (platform/GPU vendor)  |  ASN (its proxy provider)

When a cluster has seen MIN_ATTEMPTS logins in the window and at least
FAIL_RATIO of them failed, every new login from that cluster gets the
campaign_cluster signal. policy.py then forces a step-up (an emailed code)
instead of letting the password decide alone.

Trade-offs:
- Collateral: real users who share the cluster key (same browser, same GPU
  vendor, same ISP) get stepped up while the attack runs. Keys that are too
  coarse hurt more people; keys that are too fine let a bot slip under
  MIN_ATTEMPTS by spreading across more clusters (Round 4's attack).
- Detection needs volume. The first MIN_ATTEMPTS attempts in a cluster
  always get through. That is the price of not judging single requests.
- Counting failures means checking the password even for requests that you
  are about to block, which costs one password hash per attempt.
"""

LAYER = "campaign"
SIGNALS = {"campaign_cluster": "this request's cluster is failing logins like a stuffing run"}

# TODO (Round 4): tune these with tools/sweep.py and the checkpoint, then
# defend your choice in the debrief. Lower = faster detection, more collateral.
MIN_ATTEMPTS = 8
FAIL_RATIO = 0.5


def cluster_key(ctx):
    family = ctx.telemetry["fp_family"] if ctx.telemetry else "no-telemetry"
    return f"{ctx.ja4 or 'no-ja4'}|{family}|AS{ctx.edge.get('asn', 0)}"


def sense(ctx):
    stats = ctx.counters.hget_all("camp", cluster_key(ctx))
    attempts, failures = stats.get("attempts", 0), stats.get("failures", 0)
    if attempts >= MIN_ATTEMPTS and failures / attempts >= FAIL_RATIO:
        return ["campaign_cluster"]
    return []


def record(ctx, failed):
    """Call after the credential check, for every attempt, blocked or not."""
    key = cluster_key(ctx)
    ctx.counters.hbump("attempts", "camp", key)
    if failed:
        ctx.counters.hbump("failures", "camp", key)
