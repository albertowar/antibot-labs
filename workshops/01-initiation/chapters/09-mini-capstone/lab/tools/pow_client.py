"""
Chapter 6: the Python side of the proof-of-work gate. Shared by the attacks and the shoppers.

  - the solver: the same puzzle as demo_site/static/js/pow-worker.js (find a counter so that
    SHA-256("<nonce>:<counter>") has `bits` leading zero bits), on one core or on all of them
  - the protocol: read the challenge from the gate's 403 (or GET /api/challenge?type=pow),
    POST the answer to /api/challenge/verify; the pass is the session cookie's clearance
  - the scrape loop and the per-attack tally (pages, solves, bits, CPU-seconds, dollars)

Every attack's run() returns one dict (Tally.result) and prints it as one JSON line.
Threads do not help the solver: CPython's hashlib only releases the GIL for inputs over
2 KB, and a PoW candidate is ~50 bytes. Hence processes.
"""

import multiprocessing as mp
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
for p in (HERE, LAB):
    if p not in sys.path:
        sys.path.insert(0, p)

from labclient import LabClient, admin, world_pool  # noqa: E402

from defenses.pow_core import solve  # noqa: E402  (the puzzle is the same on both sides)

SKUS = [f"p{i:03d}" for i in range(1, 121)]        # the whole catalog: what the scraper wants
JSON_HEADERS = [("User-Agent", "python-httpx/0.28.1"), ("Accept", "application/json"),
                ("Accept-Encoding", "gzip, deflate")]
# Rough on-demand price of one cloud vCPU-hour. Spot capacity and botnets are cheaper.
USD_PER_VCPU_HOUR = 0.04


def bot(name, ip=None, index=0):
    """A scraper client on a rented cloud address (203.0.113.0/26)."""
    return LabClient(f"bot:{name}", ip=ip or world_pool("cloud_vm")[index])


class Tally:
    """What one attack achieved, and what it paid."""

    def __init__(self, name, wanted=len(SKUS)):
        self.name, self.wanted = name, wanted
        self.pages_ok, self.solves, self.hashes, self.cpu_s = 0, 0, 0, 0.0
        self.bits, self.notes = [], []
        self.started = time.perf_counter()

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def result(self):
        per_1k = self.cpu_s / self.pages_ok * 1000 if self.pages_ok else None
        return {"name": self.name, "pages_ok": self.pages_ok, "pages_wanted": self.wanted,
                "success": round(self.pages_ok / self.wanted, 3), "solves": self.solves, "bits": self.bits,
                "max_bits": max(self.bits, default=None), "hashes": self.hashes, "cpu_s": round(self.cpu_s, 3),
                "cpu_s_per_1k": round(per_1k, 2) if per_1k is not None else None,
                "usd_per_1k": round(per_1k / 3600 * USD_PER_VCPU_HOUR, 6) if per_1k is not None else None,
                "wall_s": round(time.perf_counter() - self.started, 2), "notes": self.notes}


# --- solving --------------------------------------------------------------------

def solve_here(challenge, tally=None):
    """Single-core solve; charges the CPU time to the tally."""
    started = time.process_time()
    counter, tried = solve(challenge["nonce"], int(challenge["difficulty"]))
    if tally is not None:
        tally.cpu_s += time.process_time() - started
        tally.hashes += tried
        tally.solves += 1
        tally.bits.append(int(challenge["difficulty"]))
    return counter


def _worker(args):
    nonce, bits, start, step, found, out = args
    started = time.process_time()
    counter, tried = solve(nonce, bits, start=start, step=step, stop=found)
    if counter is not None:
        found.set()
        out.put(counter)
    return tried, time.process_time() - started


_pool = _manager = None


def solve_parallel(challenge, tally, workers=None):
    """Split the counter space across processes: worker i tries i, i+n, i+2n, ... (as pow.js does)."""
    global _pool, _manager
    n = workers or min(os.cpu_count() or 2, 8)
    if _pool is None:
        _manager = mp.Manager()
        _pool = mp.Pool(n)
    found, out = _manager.Event(), _manager.Queue()
    bits = int(challenge["difficulty"])
    stats = _pool.map(_worker, [(challenge["nonce"], bits, i, n, found, out) for i in range(n)])
    tally.hashes += sum(t for t, _ in stats)
    tally.cpu_s += sum(c for _, c in stats)
    tally.solves += 1
    tally.bits.append(bits)
    return out.get()


def close_pool():
    global _pool, _manager
    if _pool is not None:
        _pool.terminate()
        _manager.shutdown()
        _pool = _manager = None


# --- talking to the gate -----------------------------------------------------------

def gate_payload(r):
    """The challenge in a gate 403 (JSON `challenge_required`), or None if this is not a PoW gate."""
    if r.status_code != 403:
        return None
    try:
        err = r.json().get("error", {})
    except ValueError:
        return None
    return err.get("payload") if err.get("code") == "challenge_required" and err.get("challenge") == "pow" else None


def get_challenge(c):
    r = c.get("/api/challenge?type=pow", JSON_HEADERS)
    return r.json()["payload"] if r.status_code == 200 else None


def last_reason(c):
    """Why the store refused our last answer. The lab reads it from the decision log (extra.pow_reason);
    the client only ever sees `challenge_failed`."""
    try:
        rows = admin("GET", "/lab/decisions", params={"actor": c.actor, "limit": 1})["items"]
        return (rows[-1].get("extra") or {}).get("pow_reason", "?") if rows else "?"
    except Exception:
        return "?"


def redeem(c, challenge, counter):
    """POST the solution; on success the session is cleared (the pass is the clearance)."""
    r = c.post("/api/challenge/verify", json={"type": "pow", "answer": {"challenge": challenge, "counter": counter}},
               headers=JSON_HEADERS)
    return r.status_code == 200, (None if r.status_code == 200 else last_reason(c))


def honest_pass(c, tally, payload=None, parallel=False):
    """Pay for a pass the intended way: solve the challenge the server issued."""
    challenge = payload or get_challenge(c)
    if challenge is None:
        tally.note("no challenge issued")
        return False
    counter = solve_parallel(challenge, tally) if parallel else solve_here(challenge, tally)
    ok, why = redeem(c, challenge, counter)
    if not ok:
        tally.note(f"verify refused: {why}")
    return ok


def scrape(c, tally, skus, get_pass):
    """Fetch every product; on a PoW gate call get_pass(payload) and retry once.

    Stops at the first item it cannot get, like a scraper that gives up.
    """
    for sku in skus:
        r = c.get(f"/api/products/{sku}", JSON_HEADERS)
        payload = gate_payload(r)
        if payload is not None:
            tally.note("gate: " + (r.headers.get("X-Lab-Signals") or "challenge_required"))
            if not get_pass(payload):
                break
            r = c.get(f"/api/products/{sku}", JSON_HEADERS)
        if r.status_code != 200:
            tally.note(f"{sku}: HTTP {r.status_code} {(r.headers.get('X-Lab-Signals') or '')}")
            break
        tally.pages_ok += 1


def report(result):
    print(f"  Products scraped: {result['pages_ok']}/{result['pages_wanted']} ({result['success']:.0%}) in {result['wall_s']:.1f} s")
    if result["solves"]:
        print(f"  Solves: {result['solves']} at {sorted(set(result['bits']))} bits, {result['hashes']:,} hashes, {result['cpu_s']:.2f} CPU-s")
    if result["cpu_s_per_1k"] is not None:
        print(f"  Cost: {result['cpu_s_per_1k']:.2f} CPU-s per 1,000 pages = ${result['usd_per_1k']:.6f} at ${USD_PER_VCPU_HOUR}/vCPU-hour")
    for n in result["notes"]:
        print(f"    - {n}")


def finish(result):
    """Print the human report, then the one JSON line checkpoint.py reads."""
    import json
    report(result)
    print(json.dumps(result))
