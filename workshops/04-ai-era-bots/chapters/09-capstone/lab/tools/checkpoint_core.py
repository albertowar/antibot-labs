"""
Checkpoint engine shared by every lab. A lab's tools/checkpoint.py declares ROUNDS
and calls main(ROUNDS).

    Round(level=3, description="single-use passes",
          attacks={"replay": "attacks/round2_replay.py",              # name -> script, "script --flag", argv list,
                   "replay_share": "attacks/round2_replay.py --share",  #   or a callable returning a dict
                   "pool": "attacks/round3_solver_pool.py"},
          expect={"replay": "partial", "replay_share": "blocked", "pool": "full"},
          scenario="browse",                     # population scenario run next to the attacks (None: no shoppers)
          allowed_fp=("no_js",),                 # personas a defense MAY stop this round
          bot_success_max=1.0,                   # optional cap on the scoreboard's bot share (see `metric`)
          extra_checks=[fn],                     # fn(board, results, attacks) -> (ok, message)
          solutions=("defenses/ladder.py",),     # files --catch-up installs from solutions/round<N>/
          setup=fn,                              # fn(level, caught_up) after the reset, before anything runs
                                                 #   (train a model, install state; caught_up: --catch-up ran)
          teardown=fn,                           # fn(level) after attacks and shoppers, before the board is read
                                                 #   (drain an async consumer)
          people=[...] or fn,                    # replaces population.personas() for this round
          threads=1)                             # population thread count (default 8; 1 = deterministic order)

Attack output convention: an attack script prints, as its LAST line, one JSON object with at
least {"attempted": n, "succeeded": k}; anything else it adds (bits, cpu_s, price) reaches
`extra_checks` and `metric` as attacks[name]. `expect` judges succeeded/attempted:

    full     >= 0.9          partial  between 0.1 and 0.9          blocked  <= 0.1

`attack=` (one script) still works and is named "attack".

    python tools/checkpoint.py --round 2             # check round 2: level, attacks, shoppers, thresholds
    python tools/checkpoint.py --round 2 --catch-up  # install solutions/round1..2 first
    python tools/checkpoint.py --restore             # put your own files back (the .bak copies)
    python tools/checkpoint.py --round 2 --level 1   # same round against the previous level (the "before" column)
    python tools/checkpoint.py --all --markdown       # every round, README table
    python tools/checkpoint.py --all --with-before --markdown  # rounds + their "before" runs, one process
    python tools/checkpoint.py --write-readme         # the above + rebuild the README's results block

--with-before reruns each judged round at level-1 right after it, so one invocation yields the
README table and every "before" column. Before runs report only: they never affect the exit code
(an earlier level may legitimately hurt a persona the round fixes).

--write-readme (implies --all --with-before) assembles the per-round attack results and replaces
the `| Round |` table inside the README's `<!-- results:start -->…<!-- results:end -->` block
(prose and <details> scoreboards in the block survive; annotations inside table cells do not) —
review `git diff` before committing.
"""

import argparse
import inspect
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import population  # noqa: E402
import scoreboard as sb  # noqa: E402
import labclient  # noqa: E402  (puts the lab root on sys.path)
import labnet  # noqa: E402

EXPECT = {"full": lambda r: r >= 0.9, "partial": lambda r: 0.1 < r < 0.9, "blocked": lambda r: r <= 0.1,
          "some": lambda r: r > 0.0}


@dataclass
class Round:
    level: int
    description: str = ""
    attack: object = None
    attacks: dict = field(default_factory=dict)
    expect: dict = field(default_factory=dict)
    scenario: object = "browse"
    bot_success_max: float = 1.0
    humans_hurt_max: int = 0
    legit_hurt_max: int = 0      # welcome automation (legit: actors) a defense may stop this round
    allowed_fp: tuple = ()
    metric: object = "served"
    solutions: tuple = ("defenses/ladder.py",)
    population_n: int = None
    extra_checks: list = field(default_factory=list)      # fn(board, results[, attacks]) -> (ok, message)
    setup: object = None                                  # fn(level, caught_up), after reset
    teardown: object = None                               # fn(level), after attacks + shoppers
    people: object = None                                 # list or callable -> list, for population.run
    threads: int = 8                                      # population thread count

    def attack_specs(self):
        specs = dict(self.attacks)
        if self.attack is not None and "attack" not in specs:
            specs["attack"] = self.attack
        return specs


def _call(fn, *args):
    """Call fn with as many of args as it accepts (2-arg checks written before attacks were passed still work)."""
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind == p.VAR_POSITIONAL for p in params):
        return fn(*args)
    n = len([p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)])
    return fn(*args[:n])


def catch_up(rounds, upto):
    """Install solutions/round1..upto cumulatively (backing up the student's files once)."""
    for n in range(1, upto + 1):
        src_dir = os.path.join(LAB, "solutions", f"round{n}")
        if not os.path.isdir(src_dir) or n not in rounds:
            continue
        for rel in rounds[n].solutions:
            src, dst = os.path.join(src_dir, rel), os.path.join(LAB, rel)
            if not os.path.exists(src):
                continue
            if os.path.exists(dst) and not os.path.exists(dst + ".bak"):
                shutil.copy2(dst, dst + ".bak")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print(f"  installed solutions/round{n}/{rel}")


def run_attack(spec):
    """spec: callable, "attacks/x.py", "attacks/x.py --flag", or ["attacks/x.py", "--flag"]. Returns its JSON."""
    if spec is None:
        return None
    if callable(spec):
        return spec()
    argv = shlex.split(spec) if isinstance(spec, str) else list(spec)
    path = argv[0] if os.path.isabs(argv[0]) else os.path.join(LAB, argv[0])
    env = dict(os.environ, DEMO_URL=labclient.BASE_URL, PYTHONPATH=HERE + os.pathsep + os.environ.get("PYTHONPATH", ""))
    r = subprocess.run([sys.executable, path, *argv[1:]], env=env, cwd=LAB, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:])
        raise SystemExit(f"attack {' '.join(argv)} failed (exit {r.returncode})")
    for line in reversed(r.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                break
    return {"stdout": r.stdout[-500:]}


def run_attacks(rnd):
    return {name: run_attack(spec) for name, spec in rnd.attack_specs().items()}


def success_rate(out):
    if not isinstance(out, dict) or not out.get("attempted"):
        return None
    return out.get("succeeded", 0) / out["attempted"]


def bot_metric(rnd, board, results, attacks):
    s = board["summary"]
    if callable(rnd.metric):
        return _call(rnd.metric, board, results, attacks)
    if rnd.metric == "purchases":
        bought = s["purchases"].get("bot", 0)
        total = sum(s["purchases"].values()) or 1
        return bought / total
    return (s["bot_served"] / s["bot_requests"]) if s["bot_requests"] else 0.0


def check_round(rounds, n, markdown=False, reset_store=True, level=None, caught_up=False):
    rnd = rounds[n] if level is None else replace(rounds[n], level=level)
    labclient.wait_for_store()
    print(f"\n== Round {n}: {rnd.description} (level {rnd.level})")
    labclient.set_level(rnd.level)
    if reset_store:
        labclient.reset()
    if rnd.setup:
        _call(rnd.setup, rnd.level, caught_up)
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    results = []
    t = None
    if rnd.scenario is not None:
        people = rnd.people() if callable(rnd.people) else rnd.people
        t = threading.Thread(target=lambda: results.extend(
            population.run(rnd.scenario, people=people, seed=population.SEED, n=rnd.population_n,
                           threads=rnd.threads, quiet=True)))
        t.start()
    attacks = run_attacks(rnd)
    if t is not None:
        t.join()
    if rnd.teardown:
        _call(rnd.teardown, rnd.level)
    board = labclient.scoreboard(since)
    print(sb.render(board, markdown))
    population.print_results(results)
    if attacks:
        print("\nattacks:")
        for name, out in attacks.items():
            rate = success_rate(out)
            print(f"  {name:<32} {'' if rate is None else f'{rate:.0%} succeeded'}  {json.dumps(out, default=str)[:160]}")
    judge = level is None                          # --level runs a round "before"; report, don't judge expectations
    problems = []
    share = bot_metric(rnd, board, results, attacks)
    if judge and share > rnd.bot_success_max + 1e-9:
        problems.append(f"bot success {share:.0%} > allowed {rnd.bot_success_max:.0%}")
    for name, want in (rnd.expect.items() if judge else []):
        rate = success_rate(attacks.get(name))
        if rate is None:
            problems.append(f"{name}: no attempted/succeeded in its output")
        elif not EXPECT[want](rate):
            problems.append(f"{name}: expected {want}, got {rate:.0%}")
    stopped_personas = {}
    for r in results:
        if r.get("outcome") in population.HURT:
            stopped_personas[r["persona"]] = stopped_personas.get(r["persona"], 0) + 1
    hurt = [r for r in results if r.get("outcome") in population.HURT and r["persona"] not in rnd.allowed_fp]
    if len(hurt) > rnd.humans_hurt_max:
        problems.append(f"{len(hurt)} shoppers stopped who should not be: " + ", ".join(sorted({r['actor'] for r in hurt})))
    legit_hurt = board["summary"].get("legit_hurt", 0)
    if judge and legit_hurt > rnd.legit_hurt_max:
        problems.append(f"{legit_hurt} legit automation actors stopped (false positives), allowed {rnd.legit_hurt_max}")
    for fn in (rnd.extra_checks if judge else []):
        good, msg = _call(fn, board, results, attacks)
        if not good:
            problems.append(msg)
    ok = not problems
    print(f"\nRound {n} at level {rnd.level}: {'PASS' if ok else 'FAIL'}" + ("" if ok else "\n  - " + "\n  - ".join(problems)))
    return {"round": n, "level": rnd.level, "ok": ok, "bot_success": round(share, 3), "humans_hurt": len(hurt),
            "stopped_personas": stopped_personas,   # every stopped shopper, allowed_fp included (README column)
            "problems": problems, "attacks": attacks, "summary": board["summary"]}


RESULTS_START, RESULTS_END = "<!-- results:start -->", "<!-- results:end -->"


def results_table(rounds, judged, before):
    """The README expected-results table, from judged runs and their 'before' runs (dicts keyed by round)."""
    lines = ["| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |",
             "|---|---|---|---|---|"]

    def cell(out, name):
        a = (out or {}).get("attacks", {}).get(name)
        if not isinstance(a, dict) or not a.get("attempted"):
            return "—"
        return f"{a.get('succeeded', 0)}/{a['attempted']}"

    for n in sorted(judged):
        stopped = judged[n].get("stopped_personas", {})
        summary = ", ".join(f"{p} {c}" for p, c in sorted(stopped.items())) or "none"
        names = list(rounds[n].attack_specs()) or ["—"]
        for i, name in enumerate(names):
            attack = f"`{name}`" if name != "—" else "—"
            lines.append(f"| {n if i == 0 else ''} | {attack} | {cell(before.get(n), name)}"
                         f" | {cell(judged[n], name)} | {summary if i == 0 else ''} |")
    return "\n".join(lines)


def write_results_block(table):
    """Replace the before/after table inside the README's results:start/end block, in place.

    Only the contiguous `|`-table starting at the block's `| Round |` header is replaced; the
    prose and <details> scoreboards that share the block survive. Returns False when the markers
    (or the table header inside them) are missing.
    """
    path = os.path.join(LAB, "README.md")
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines(keepends=True)
    try:
        start = next(i for i, ln in enumerate(lines) if RESULTS_START in ln)
        end = next(i for i, ln in enumerate(lines) if RESULTS_END in ln)
        first = next(i for i in range(start, end) if lines[i].lstrip().startswith("| Round |"))
    except StopIteration:
        return False
    last = first
    while last + 1 < end and lines[last + 1].lstrip().startswith("|"):
        last += 1
    lines[first:last + 1] = [table + "\n"]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(lines))
    return True


def report_results_block(rounds, out, before):
    table = results_table(rounds, {o["round"]: o for o in out}, before)
    print("\n" + table)
    if write_results_block(table):
        print("\nwrote the README.md results table (annotations in table cells are replaced - review `git diff`)")
    else:
        print("\nno results:start/end block with a '| Round |' table in README.md; paste the table into its"
              " Expected results section")


def main(rounds):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, default=None)
    ap.add_argument("--level", type=int, default=None, help="run the round's attacks at another level (e.g. N-1: the 'before')")
    ap.add_argument("--with-before", action="store_true",
                    help="after each judged round, rerun it at level-1 (the 'before' column); reported, not judged")
    ap.add_argument("--write-readme", action="store_true",
                    help="rebuild the README's results:start/end block from this run (implies --all --with-before)")
    ap.add_argument("--catch-up", action="store_true", help="install solutions/round1..N before checking")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--restore", action="store_true", help="put back the student files --catch-up replaced (.bak)")
    args = ap.parse_args()
    if args.restore:
        for rel in labnet.restore(LAB):
            print(f"  restored {rel}")
        return
    if args.write_readme:
        args.all = args.with_before = True
    if args.round is None and not args.all:
        ap.error("--round N, --all or --restore")
    todo = sorted(rounds) if args.all else [args.round]
    if args.catch_up:
        catch_up(rounds, max(todo))
    out, before = [], {}
    for n in todo:
        out.append(check_round(rounds, n, args.markdown, not args.no_reset, args.level, args.catch_up))
        if args.with_before and args.level is None and rounds[n].level > 0:
            before[n] = check_round(rounds, n, args.markdown, not args.no_reset, rounds[n].level - 1, args.catch_up)
    if args.write_readme:
        report_results_block(rounds, out, before)
    if args.json:
        print(json.dumps(out, indent=1, default=str))
    sys.exit(0 if all(o["ok"] for o in out) else 1)
