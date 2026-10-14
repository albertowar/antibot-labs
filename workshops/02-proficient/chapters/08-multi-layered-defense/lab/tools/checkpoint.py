"""
Round checkpoint for W2 Ch8 (Multi-Layered Defense Architecture). Declares the rounds and hands
over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, sign the 200 customers in
    python tools/checkpoint.py --round 3 --level 2    # the same customers against Round 2's engine (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 (ladder.py, policy.py), your files kept as .bak
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is PRE-WRITTEN: every layer ships complete, and a round is a DEFENSE_LEVEL (the store
switches level without a restart; the checkpoint sets it). Catching up means running the round at its
level, which is what this does; `--catch-up` additionally restores the reference ladder.py and
policy.py, undoing your experiments with weights and lines.

    round  level adds                                      what the 200 customers should see
    -----  ----------------------------------------------  ----------------------------------------------
      0    shadow mode: layers run and log, nothing enforced  nobody blocked, nobody challenged
      1    the veto chain: any layer over its own line blocks  5-25% of real customers blocked (the lesson)
      2    the risk score and the response ladder             <= 1% blocked, friction instead (<= 15%)
      3    + correlation; a block looks like a typo           same budget; every block is deceptive
      4    + campaign layer and step-up                       same budget; step-up only if a cluster is hot

There is NO attack script: each round's attacker is a signal profile you score with
`python tools/sweep.py --signals a,b,c` (see the README). What runs live is the cost side, the 200
people of tools/personas_ch8.py, one at a time, with the numbers the budget checks below judge.

Defender cost: the gate time of each person's first sign-in (Server-Timing), and the CPU the proof of
work cost a Python client (a browser's WebCrypto is faster).
"""

import os
import random
import statistics
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch8  # noqa: E402  (swaps in the 200 customers and the `ch8_login` scenario)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402
import report  # noqa: E402

# (max % blocked, min % blocked, max % challenged) of real customers, per level
BUDGET = {
    0: (0.0, 0.0, 0.0),     # shadow mode: nothing enforced
    1: (25.0, 5.0, 0.0),    # veto chain: real customers get blocked, and that is the point
    2: (1.0, 0.0, 15.0),    # score + ladder: friction instead of blocks
    3: (1.0, 0.0, 15.0),    # + correlation: the budget must not move
    4: (1.0, 0.0, 15.0),    # + campaign: same budget, step-up only when a cluster is hot
}
GATE_MEDIAN_MAX_MS = 20.0           # in-process Redis
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # a real Redis: ~10 round trips per login


# The log's `action` column is the highest-SCORE decision of the request, so a campaign step-up (0 points) reads
# "allow" there; `outcome` is what the client actually got.
STOPPED = ("blocked", "deceived", "challenged")


def show(board, results, attacks):
    """Who paid, what they paid for, and the defender's cost. Printed on every run, also `--level N-1`
    (the "before" column), because Round's `metric` is called then; there is no bot share to return."""
    total = len(results)
    blocked = [r for r in results if r.get("outcome") == "blocked"]
    stuck = [r for r in results if r.get("outcome") == "stuck_on_challenge"]
    chal = [r for r in results if r.get("challenge")]
    rung = Counter(r["challenge"] for r in chal)
    rows = report.attempts(report.read_log())
    level = rows[0]["level"] if rows else 0
    print(f"\nReal customers ({total} logins, level {level})")
    print(f"  blocked     {len(blocked):>4}  {report.pct(len(blocked), total)}"
          + ("   (shown as 'Wrong email or password')" if level >= 3 and blocked else ""))
    print(f"  challenged  {len(chal):>4}  {report.pct(len(chal), total)}   pow {rung['pow']}, step-up {rung['step_up']}"
          f"   (all solved: {not stuck})")
    print("\n  Who paid")
    pops = Counter(r["persona"] for r in results)
    paid = personas_ch8.summarize([r for r in results if r.get("outcome") == "blocked" or r.get("challenge")])
    for name, row in paid.items():
        acts = ", ".join(f"{k} {row[k]}" for k in ("blocked", "pow", "step_up") if row[k])
        print(f"    {name:<22} {row['people']:>3}/{pops[name]:<3} {acts}")
    why = Counter(s for e in rows if e["outcome"] in STOPPED for s in report.flat_signals(e))
    if why:
        print("  Signals they paid for: " + ", ".join(f"{s} {n}" for s, n in why.most_common(6)))
    if level == 1:
        from defenses import policy, veto
        by = Counter(veto.blocking_layer([(layer, policy.WEIGHTS.get(n, 0)) for layer, names in report.layers(e).items()
                                          for n in names]) for e in rows if e["outcome"] == "blocked")
        print("  Vetoed by: " + ", ".join(f"{layer} {n}" for layer, n in by.most_common()))
    ms = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
    if ms:
        median, p95 = report.percentiles(ms)
        print(f"\nDefender cost\n  gate per login: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} logins")
    pows = [r["pow_ms"] for r in results if r.get("pow_ms")]
    if pows:
        print(f"  proof-of-work: median {statistics.median(pows):.0f} ms per challenged customer (Python; a browser's WebCrypto is faster)")
    if ms:
        steps = f"{rung['pow']} proof of work" + (f", {rung['step_up']} step-up" if rung["step_up"] else "")
        print(f"\nREADME row: | {level} | {len(blocked)} ({100 * len(blocked) / total:.1f}%) | "
              f"{len(chal)} ({100 * len(chal) / total:.1f}%){' = ' + steps if chal else ''} | {median:.1f} ms |")
    return 0.0


def budget(level):
    """Did the customers stay inside this level's budget?"""
    max_block, min_block, max_chal = BUDGET[level]

    def check(board, results, attacks):
        total = len(results)
        blocked = [r for r in results if r.get("outcome") == "blocked"]
        stuck = [r for r in results if r.get("outcome") == "stuck_on_challenge"]
        chal = [r for r in results if r.get("challenge")]
        problems = []
        block_rate, chal_rate = 100 * len(blocked) / total, 100 * len(chal) / total
        if block_rate > max_block:
            problems.append(f"blocked {block_rate:.1f}% of real customers, budget {max_block:.0f}%")
        if block_rate < min_block:
            problems.append(f"blocked only {block_rate:.1f}%; at this level the veto chain should hurt")
        if chal_rate > max_chal:
            problems.append(f"challenged {chal_rate:.1f}%, budget {max_chal:.0f}%")
        if stuck:
            problems.append(f"{len(stuck)} customers could not complete their challenge")
        typos = [r for r in results if "typo" in r["persona"]]
        if any(r.get("outcome") not in ("typo_rejected", "blocked", "stuck_on_challenge") for r in typos):
            problems.append("a typo should be answered 401 (or be one of the blocked)")
        return (not problems, "; ".join(problems))
    return check


def cost(board, results, attacks):
    ms = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
    if not ms:
        return (False, "no gate timings in the responses")
    median, _ = report.percentiles(ms)
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


NVIDIA = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)"


def _browser(ip, seed=7):
    """A clean Chrome-on-Windows session with its telemetry posted. Probes are labelled `lab:probe`, so
    neither the scoreboard nor the sweep counts them as customers. The home_eu pool is used by nobody else."""
    rng = random.Random(seed)
    client = labclient.LabClient("lab:probe:000", ip=ip, rng=rng, ja4=personas_ch8.sensor_tls.JA4["chrome"])
    headers = personas_ch8.browser_headers("chrome-win")
    client.get("/login", headers)
    fp = personas_ch8.fingerprint(rng, "chrome-win", "Europe/Berlin", ["en-US", "en"])
    fp["webgl_renderer"] = NVIDIA
    client.post("/api/telemetry", json={"kind": "risk", "fp": fp, "behavior": {
        "mouse": personas_ch8.human_path(rng), "keys": personas_ch8.keystrokes(rng, 30), "pointer_type": "mouse"}}, headers=headers)
    return client, headers


def _wrong(honeypot):
    """A wrong password from a clean browser session; with `honeypot` the hidden field is filled too."""
    client, headers = _browser(labclient.world_pool("home_eu")[1 if honeypot else 0])
    r = client.post("/api/login", json={"email": "user100@example.test", "password": "not-the-password",
                                        "website": "http://spam.example" if honeypot else ""}, headers=headers)
    return r, client.verdict()


def opaque(board, results, attacks):
    """From level 3 a block must be indistinguishable from a typo."""
    typo, _ = _wrong(False)
    blocked, verdict = _wrong(True)
    same = (typo.status_code, typo.content) == (blocked.status_code, blocked.content)
    print(f"\nA block vs. a typo: {typo.status_code} / {blocked.status_code}, store verdict for the second: "
          f"{verdict[0] if verdict else None}, bodies {'identical' if same else 'DIFFER'}")
    if not verdict or verdict[0] != "deceive":
        return (False, f"the honeypot probe was not blocked deceptively (verdict {verdict})")
    return (same, "a block answers differently from a wrong password: the client can tell")


def campaign_probe(board, results, attacks):
    """Make one cluster hot with a burst of failed logins (a stuffing run from AS64499, Chrome on NVIDIA),
    then sign in as a real customer who happens to share that cluster. The policy must ask the customer
    for an emailed code (CAMPAIGN_ACTION), and the code must work: the collateral the README quantifies."""
    from defenses import policy
    pool = labclient.world_pool("home_eu")
    burst, headers = _browser(pool[2], seed=11)
    for i in range(12):
        burst.post("/api/login", json={"email": f"user{110 + i}@example.test", "password": "combo-list-guess", "website": ""},
                   headers=headers, ip=pool[3 + i])
    customer, headers = _browser(pool[20], seed=13)
    email = personas_ch8.username(101)
    r = customer.post("/api/login", json={"email": email, "password": personas_ch8.password_for(101), "website": ""}, headers=headers)
    err = (r.json().get("error") or {}) if r.status_code == 403 else {}
    kind = err.get("challenge")
    print(f"\nA customer in the hot cluster: {r.status_code} {err.get('code', '')} {kind or ''}  (CAMPAIGN_ACTION = {policy.CAMPAIGN_ACTION})")
    if policy.CAMPAIGN_ACTION == "block":
        return (r.status_code in (401, 403), "a hot cluster should refuse the customer under CAMPAIGN_ACTION = block")
    if kind != policy.CAMPAIGN_ACTION:
        return (False, f"the hot cluster should serve {policy.CAMPAIGN_ACTION}, got {r.status_code} {kind}")
    probe = {"challenge": ""}
    ok = personas_ch8._complete(customer, headers, email, kind, err["payload"], probe)
    done = ok and customer.post("/api/login", json={"email": email, "password": personas_ch8.password_for(101), "website": ""},
                                headers=headers).status_code == 200
    print(f"  completed the {kind} ({'emailed code' if kind == 'step_up' else 'proof of work'}) and signed in: {done}")
    return (done, f"the customer could not complete the {kind} and sign in")


def make_round(level, description):
    extra = [budget(level), cost] + ([opaque] if level >= 3 else []) + ([campaign_probe] if level >= 4 else [])
    return Round(level=level, description=description, scenario="ch8_login", humans_hurt_max=BUDGET_HURT[level], metric=show,
                 extra_checks=extra, solutions=("defenses/ladder.py", "defenses/policy.py"))


# The core's own "shoppers stopped" check; the budget above is the real judge. 25% of 200 for the veto chain.
BUDGET_HURT = {0: 0, 1: 50, 2: 2, 3: 2, 4: 2}

ROUNDS = {
    0: make_round(0, "L0 shadow mode: every layer runs and logs, nothing is enforced"),
    1: make_round(1, "L1 the veto chain: any one layer over its own line blocks"),
    2: make_round(2, "L2 one risk score and a response ladder"),
    3: make_round(3, "L3 correlation layer; a block looks like a typo"),
    4: make_round(4, "L4 campaign layer and step-up"),
}

if __name__ == "__main__":
    main(ROUNDS)
