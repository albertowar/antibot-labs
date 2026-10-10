"""
Chapter 4 — Round 4 Attack: Noise on Every Sign-up (Section 4.7)

Objective: break linking. The attacker keeps the harvested device but does
what anti-detect browsers call "noise mode": a fresh canvas hash and audio
value on every sign-up, plus a different CPU core count. The payload is
still internally consistent (page and worker agree), so L1 and L2 stay
quiet, and every stable_id is brand new, so L3 never sees a repeat.

Privacy browsers (Brave, Firefox FPP, Safari 26) add the same kind of noise
for every user. That is why the defense in this round can't treat noise as
guilt.

Expected results:
  - DEFENSE_LEVEL<=3: 20/20 created (every stable_id is unique)
  - DEFENSE_LEVEL=4:  3/20, then "[L4] fingerprint_cluster: 3 accounts today from near-identical devices ..."

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then:
    python attacks/round4_noise_signup.py [--signups 20] [--payload you.json]
"""

import argparse
import copy
import random
import secrets

from playwright.sync_api import sync_playwright

from _lab import bot_email, lab_ip, report, require_local
from round3_replay_signup import HARVESTED, load_payload, replay_signup


def add_noise(fp, rng):
    """New render hashes and a jittered core count, applied to page AND worker."""
    fp = copy.deepcopy(fp)
    canvas_hash = secrets.token_hex(8)
    fp["canvas"].update({"hash": canvas_hash, "hash2": canvas_hash})  # stable within the visit
    fp["audio"]["sum"] = round(fp["audio"]["sum"] + rng.uniform(-1e-4, 1e-4), 6)
    fp["audio"]["hash"] = secrets.token_hex(8)
    cores = rng.choice([8, 12, 16])
    fp["nav"]["hardwareConcurrency"] = cores
    fp["worker"]["hardwareConcurrency"] = cores
    # TODO (Round 4, attacker): also jitter the screen size. Does L4 still
    # cluster the accounts? Which defender TODO in fuzzy_cluster.py fixes it?
    return fp


def run(signups=20, verbose=False, payload_path=HARVESTED, seed=4):
    require_local()
    base = load_payload(payload_path)
    rng = random.Random(seed)
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(signups):
            context = browser.new_context(extra_http_headers={"X-Lab-Client-IP": lab_ip(i)})
            results.append(replay_signup(context, add_noise(base, rng), bot_email(4, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 4: harvested fingerprint + per-sign-up noise", results)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--signups", type=int, default=20)
    parser.add_argument("--payload", default=HARVESTED, help="harvested payload or /fp-profile download")
    args = parser.parse_args()
    run(args.signups, verbose=True, payload_path=args.payload)
