"""
Chapter 2, Round 4 attack: noise on every sign-up (Section 2.7).

Objective: break linking. The attacker keeps the harvested device but does what anti-detect
browsers call "noise mode": a fresh canvas hash and audio value on every sign-up, plus a different
CPU core count. The payload is still internally consistent (page and worker agree), so L1 and L2
stay quiet, and every stable_id is brand new, so L3 never sees a repeat.

Privacy browsers (Brave, Firefox FPP, Safari 26) add the same kind of noise for every user. That
is why the defense in this round cannot treat noise as guilt.

Expected results:
  - DEFENSE_LEVEL<=3: 20/20 created (every stable_id is unique)
  - DEFENSE_LEVEL=4:  3/20, then fp:fingerprint_cluster ("3 accounts today from near-identical devices ...")

Run the store first, set the level (3 to see it succeed, 4 to see it stopped), then:
    python attacks/round4_noise_signup.py [--signups 20] [--payload you.json]

tools/checkpoint.py passes --payload attacks/data/harvested_fp_b.json, a second harvested PC:
it runs every bot on one store, and Round 3's accounts (the first PC) would otherwise seed this
round's cluster. By hand, with a reset between the two attacks, the first PC gives the same 3.
"""

import copy
import random
import secrets

from playwright.sync_api import sync_playwright

from _common import bot_email, common_args, finish, new_context, report, reset
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
    base = load_payload(payload_path)
    rng = random.Random(seed)
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(signups):
            context = new_context(browser, "round4_noise_signup", i)
            results.append(replay_signup(context, add_noise(base, rng), bot_email(4, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 4: harvested fingerprint + per-sign-up noise", results)
    return results


if __name__ == "__main__":
    args = common_args(__doc__.split("\n")[1], payload=HARVESTED).parse_args()
    if not args.no_reset:
        reset()
    finish("round4_noise_signup", run(args.signups, verbose=True, payload_path=args.payload))
