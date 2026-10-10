"""
Chapter 9 — L4 login risk: failures per fingerprint cluster (W2 Ch6)

Credential stuffing has one statistical signature no proxy pool can hide:
most attempts fail. Real users mistype now and then; a combo list fails
90–99% of the time. The question is what to count failures *per*:

    per IP            useless once the attacker rotates residential proxies
    per account       catches brute force, not stuffing (one try per account)
    per fingerprint   what token binding makes possible: every attempt is tied
                      to one JA4 + fingerprint hash, and a stuffer replays one
                      captured fingerprint or runs one browser build

    cluster = JA4 + fingerprint hash
    >= MIN_FAILURES failures and failure ratio >= MAX_FAILURE_RATIO in WINDOW_S  ->  +60

This check runs *before* the password is verified. That matters: a step-up
("we emailed you a code") only answers after a correct password, so a stuffer
that sees step-up replies has still learned which credentials work and can
sell them. Blocking the cluster first means it learns nothing more.

Where it fails:
  - Identical corporate laptops share a fingerprint hash; one user locked
    out by typos can drag the cluster's ratio up (that's why MIN_FAILURES).
  - A patient attacker who rotates real devices (a phone farm) has many
    clusters. That's W3 territory: device attestation.
"""

import hashlib
import time

WINDOW_S = 600
MIN_FAILURES = 5
MAX_FAILURE_RATIO = 0.5


def cluster_key(ctx, state):
    return f"{ctx['ja4']}|{state['fp_hash'] or 'no-telemetry'}"


def cluster_id(cluster):
    return hashlib.sha256(cluster.encode()).hexdigest()[:12]


def _keys(cluster):
    bucket = int(time.time() // WINDOW_S)
    cid = cluster_id(cluster)
    return f"lr:{cid}:{bucket}:total", f"lr:{cid}:{bucket}:fail"


def record_attempt(store, cluster, valid):
    total_key, fail_key = _keys(cluster)
    pipe = store.pipeline()
    pipe.incr(total_key)
    if not valid:
        pipe.incr(fail_key)
    pipe.expire(total_key, WINDOW_S * 2)
    pipe.expire(fail_key, WINDOW_S * 2)
    pipe.execute()


def cluster_counts(store, cluster):
    total_key, fail_key = _keys(cluster)
    return int(store.get(total_key) or 0), int(store.get(fail_key) or 0)


def score_cluster(store, cluster):
    total, failures = cluster_counts(store, cluster)
    # TODO (Round 4): block the cluster (return 60 and a reason) when it has
    # at least MIN_FAILURES failures AND failures / total >= MAX_FAILURE_RATIO.
    # Run attacks/round4_stuffing.py --with-token before and after, and compare
    # the "credentials confirmed" line.
    return 0, []


if __name__ == '__main__':
    print(cluster_id("t13d1516h2_8daaf6152771_x|abcd"))
