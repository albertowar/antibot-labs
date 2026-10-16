"""
In-process verification harness (build time; not part of the student flow).

Starts the store on a background thread in THIS process on a free port (or $PORT),
waits for it, then runs the checkpoint (or the smoke test) against it and exits with
its status. One foreground process, so it works in CI, in sandboxes that reap daemons,
and with several agents verifying different labs at once.

    python tools/verify.py --smoke
    python tools/verify.py --round 2                 # round 2 at its own level
    python tools/verify.py --round 2 --level 1       # round 2's attacks against level 1 (the "before")
    python tools/verify.py --round 2 --catch-up      # install solutions/round1..2 first
    python tools/verify.py --all --markdown          # every round: the README expected-results table
    python tools/verify.py --all --with-before --markdown  # rounds + their "before" columns, one process

--with-before reruns each judged round at level-1 right after it (the README "before" column),
so the whole exit-criteria sweep is one invocation plus --smoke. Before runs report only: they
never affect the exit code (an earlier level may legitimately hurt a persona the round fixes).
"""

import argparse
import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path[:0] = [LAB, HERE]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


PORT = int(os.environ.get("PORT") or free_port())
BASE = f"http://127.0.0.1:{PORT}"
# labclient reads DEMO_URL at import time, so set it before anything imports it.
os.environ["PORT"], os.environ["DEMO_URL"] = str(PORT), BASE


def start_store(level):
    os.environ["DEFENSE_LEVEL"] = str(level)
    os.environ.setdefault("REDIS_URL", "memory://")
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(LAB, 'instance', f'verify-{PORT}.db')}")
    from werkzeug.serving import make_server
    from demo_site.app import create_app
    app = create_app()
    srv = make_server("127.0.0.1", PORT, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return app, srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=None)
    ap.add_argument("--level", type=int, default=None)
    ap.add_argument("--with-before", action="store_true",
                    help="after each judged round, rerun it at level-1 (the 'before' column); reported, not judged")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    app, srv = start_store(args.level if args.level is not None else (args.round or 0))
    print(f"[verify] store on {BASE}")
    try:
        import labclient
        labclient.wait_for_store()
        if args.smoke:
            import smoke
            return smoke.run()
        import checkpoint
        import checkpoint_core
        rounds = sorted(checkpoint.ROUNDS) if args.all else [args.round or 0]
        if args.catch_up:
            checkpoint_core.catch_up(checkpoint.ROUNDS, max(rounds))
        outs = []
        for n in rounds:
            outs.append(checkpoint_core.check_round(checkpoint.ROUNDS, n, args.markdown, True, args.level))
            if args.with_before and args.level is None and checkpoint.ROUNDS[n].level > 0:
                checkpoint_core.check_round(checkpoint.ROUNDS, n, args.markdown, True, checkpoint.ROUNDS[n].level - 1)
        return 0 if all(o["ok"] for o in outs) else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
