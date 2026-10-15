"""
The campaign layer (switched on by the operator: config.campaign)

Every session of a credential-stuffing run can look human: fresh fingerprint, fresh trace, fresh
IP. What it cannot hide is the *campaign*. A run fails almost every login, because most of the
combo list does not match your users. Real people fail roughly one login in ten.

So we stop judging requests and judge clusters. The cluster key is what the attacker's tooling
holds constant while it rotates everything else:

    JA4 (its TLS stack)  |  device family (platform/GPU vendor)  |  ASN (its proxy provider)

When a cluster has seen MIN_ATTEMPTS logins in the window and at least FAIL_RATIO of them failed,
every new login from that cluster gets the campaign_cluster signal. policy.decide() then forces
the challenge named by policy.CAMPAIGN_ACTION (an emailed code by default) instead of letting the
password decide alone.

Trade-offs:
- Collateral: real users who share the cluster key (same browser, same GPU vendor, same ISP) get
  stepped up while the attack runs. Keys that are too coarse hurt more people; keys that are too
  fine let a bot slip under MIN_ATTEMPTS by spreading across more clusters.
- Detection needs volume. The first MIN_ATTEMPTS attempts in a cluster always get through. That
  is the price of not judging single requests.
- Counting failures means checking the password even for requests that you are about to
  challenge or block, which costs one password hash per attempt (demo_site/ext/ops.py does it in an
  enricher, and only while the campaign layer is on).
- It is a blunt containment tool, so it carries a TTL (tools/contain.py --campaign-stepup).
"""


from . import attempt, features, ops, policy, sensors
from .pipeline import Check, Signal, Verdict
from .sensors import LOGIN

LAYER = "campaign"
SIGNALS = {"campaign_cluster": "this request's cluster is failing logins like a stuffing run"}

# Tune these with tools/sweep.py --clusters, then defend your choice in the debrief.
# Lower = faster detection, more collateral.
MIN_ATTEMPTS = 8
FAIL_RATIO = 0.5
WINDOW = 600


def _check(ctx):
    if not ops.state(ctx)["cfg"].get("campaign"):
        return None
    key = features.cluster_key(ctx)
    redis, k = ctx.redis, f"lab:ops:w:camp:{key}"
    stats = {f: int(v) for f, v in redis.hgetall(k).items()}
    attempts, failures = stats.get("attempts", 0), stats.get("failures", 0)
    hot = attempts >= MIN_ATTEMPTS and failures / attempts >= FAIL_RATIO
    cred = ctx.attrs.get("ops_cred")            # the enricher checked the password (valid|wrong|unknown)
    if cred is not None and not attempt.resumed(ctx):
        redis.hincrby(k, "attempts", 1)
        if cred != "valid":
            redis.hincrby(k, "failures", 1)
        redis.expire(k, WINDOW)
    if not hot:
        return None
    sig = sensors.emit(ctx, LAYER, ["campaign_cluster"])[0]
    sig = Signal(LAYER, sig.name, sig.points, f"{failures}/{attempts} failed")
    challenge = policy.CAMPAIGN_ACTION if policy.CAMPAIGN_ACTION in ("pow", "step_up") else None
    return Verdict(action="allow", signals=(sig,), challenge=challenge)


CHECK = Check("campaign", _check, phases=LOGIN)
