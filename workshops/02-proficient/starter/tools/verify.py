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
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    if args.smoke:
        # The contract test sees the bare store: the gate runs an empty ladder at every level,
        # so a lab with a permanent baseline at LADDER[0] still passes (contract 1.7).
        os.environ["LAB_SMOKE"] = "1"
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
        outs = [checkpoint_core.check_round(checkpoint.ROUNDS, n, args.markdown, True, args.level, args.catch_up) for n in rounds]
        return 0 if all(o["ok"] for o in outs) else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
