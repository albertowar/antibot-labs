"""
Chapter 7 — Shared attacker plumbing (not an attack by itself)

  - refuses any target that is not this machine (rules of engagement)
  - an httpx client that presents a simulated client IP (X-Sim-Client-IP)
  - the PoW client: fetch a challenge, solve it, redeem it for a pass
  - a multi-core solver: the same puzzle, split across processes
  - the scrape loop and the per-attack scoreboard (Tally)

Every attack's run() returns one dict (see Tally.result) that
tools/checkpoint.py turns into the scoreboard.

Simulated IPs come from the documentation ranges (RFC 5737), so they can
never be anybody's real address: 203.0.113.0/24 for bots, 198.51.100.0/24
for real users, and 100.64.0.0/10 (RFC 6598 shared address space) for the
CGNAT household.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
import time
from urllib.parse import urlparse

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))
from pow_core import solve  # noqa: E402  (the puzzle is the same on both sides)

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAGES = 200
BOT_IP = "203.0.113.66"
# Rough on-demand price of one cloud vCPU-hour. Spot capacity and botnets are cheaper.
USD_PER_VCPU_HOUR = 0.04


def require_local(url: str) -> str:
    """Rules of engagement: these scripts only ever talk to this machine."""
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        raise SystemExit(f"❌ Refusing to attack {url}: lab scripts only target localhost. "
                         "Run them against your own demo site.")
    return url


require_local(BASE_URL)


def client(ip: str = BOT_IP, user_agent: str | None = None) -> httpx.Client:
    headers = {"X-Sim-Client-IP": ip}
    if user_agent:
        headers["User-Agent"] = user_agent
    return httpx.Client(base_url=BASE_URL, headers=headers, timeout=60)


def is_pow_gate(r: httpx.Response) -> bool:
    if r.status_code != 403:
        return False
    try:
        return r.json().get("error") == "pow_required"
    except ValueError:
        return False


def reasons(r: httpx.Response) -> list[str]:
    try:
        return r.json().get("reasons", [])
    except ValueError:
        return [f"HTTP {r.status_code}"]


class Tally:
    """What one attack achieved, and what it paid."""

    def __init__(self, name: str, wanted: int = PAGES):
        self.name, self.wanted = name, wanted
        self.pages_ok, self.solves, self.hashes, self.cpu_s = 0, 0, 0, 0.0
        self.bits: list[int] = []
        self.notes: list[str] = []
        self.started = time.perf_counter()

    def note(self, text: str):
        if text not in self.notes:
            self.notes.append(text)

    def result(self) -> dict:
        per_1k = self.cpu_s / self.pages_ok * 1000 if self.pages_ok else None
        return {
            "name": self.name, "pages_ok": self.pages_ok, "pages_wanted": self.wanted,
            "success": self.pages_ok / self.wanted, "solves": self.solves,
            "bits": self.bits, "max_bits": max(self.bits, default=None),
            "hashes": self.hashes, "cpu_s": self.cpu_s,
            "cpu_s_per_1k": per_1k,
            "usd_per_1k": per_1k / 3600 * USD_PER_VCPU_HOUR if per_1k is not None else None,
            "wall_s": time.perf_counter() - self.started, "notes": self.notes,
        }


# --- solving ------------------------------------------------------------------

def solve_here(challenge: dict, tally: Tally) -> int:
    """Single-core solve; charges the CPU time to the tally."""
    started = time.process_time()
    counter, tried = solve(challenge["nonce"], int(challenge["difficulty"]))
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


_pool = None
_manager = None


def solve_parallel(challenge: dict, tally: Tally, workers: int | None = None) -> int:
    """Split the counter space across processes: worker i tries i, i+n, i+2n, ...

    Threads would not help: CPython's hashlib only releases the GIL for
    inputs over 2 KB, and a PoW candidate is ~50 bytes.
    """
    global _pool, _manager
    n = workers or min(os.cpu_count() or 2, 8)
    if _pool is None:
        _manager = mp.Manager()
        _pool = mp.Pool(n)
    found, out = _manager.Event(), _manager.Queue()
    nonce, bits = challenge["nonce"], int(challenge["difficulty"])
    stats = _pool.map(_worker, [(nonce, bits, i, n, found, out) for i in range(n)])
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


# --- talking to the gate ---------------------------------------------------------

def get_challenge(c: httpx.Client) -> dict | None:
    r = c.get("/pow/challenge")
    return r.json() if r.status_code == 200 else None


def redeem(c: httpx.Client, challenge: dict, counter) -> tuple[bool, list[str]]:
    """POST the solution; on success the pass cookie lands in c's cookie jar."""
    r = c.post("/pow/verify", json={"challenge": challenge, "counter": counter})
    return r.status_code == 200, reasons(r)


def honest_pass(c: httpx.Client, tally: Tally, parallel: bool = False) -> bool:
    """Pay for a pass the intended way: solve the challenge the server issued."""
    challenge = get_challenge(c)
    if challenge is None:
        tally.note("no challenge issued")
        return False
    counter = solve_parallel(challenge, tally) if parallel else solve_here(challenge, tally)
    ok, why = redeem(c, challenge, counter)
    if not ok:
        tally.note(f"verify refused: {why}")
    return ok


def scrape(c: httpx.Client, tally: Tally, pages, get_pass) -> None:
    """Fetch every page; when the gate says 'pow_required', call get_pass() and retry once.

    Stops at the first page it cannot get, like a scraper that gives up.
    """
    for page in pages:
        r = c.get("/api/products", params={"page": page})
        if is_pow_gate(r):
            tally.note(f"gate: {reasons(r)[0] if reasons(r) else 'pow_required'}")
            if not get_pass():
                break
            r = c.get("/api/products", params={"page": page})
        if r.status_code != 200:
            tally.note(f"page {page}: {r.status_code} {reasons(r)}")
            break
        tally.pages_ok += 1


def report(result: dict) -> None:
    print(f"  Pages scraped: {result['pages_ok']}/{result['pages_wanted']} "
          f"({result['success']:.0%})  in {result['wall_s']:.1f} s")
    if result["solves"]:
        bits = sorted(set(result["bits"]))
        print(f"  Solves: {result['solves']} at {bits} bits · {result['hashes']:,} hashes · "
              f"{result['cpu_s']:.2f} CPU-s")
    if result["cpu_s_per_1k"] is not None:
        print(f"  Cost: {result['cpu_s_per_1k']:.2f} CPU-s per 1,000 pages "
              f"≈ ${result['usd_per_1k']:.6f} at ${USD_PER_VCPU_HOUR}/vCPU-hour")
    for n in result["notes"]:
        print(f"    - {n}")
    print()
