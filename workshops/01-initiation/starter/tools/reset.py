"""Reset the store between rounds: POST /lab/reset (state) or --full to reseed. Direct DB reset if the store is down."""

import argparse
import sys

from labclient import reset

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="drop and reseed everything")
    ap.add_argument("--stock", type=int, default=None, help="drop stock to restore")
    a = ap.parse_args()
    params = {"stock": a.stock} if a.stock else {}
    try:
        print(reset("full" if a.full else "state", **params))
    except Exception as e:
        print(f"store not reachable ({e!r}); resetting the database directly")
        sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
        from demo_site.app import create_app
        from demo_site.seed import reset_state, seed_all
        app = create_app(seed=False)
        with app.app_context():
            cfg = app.config["LAB"]
            print(seed_all(cfg.lab_seed, cfg.drop_stock, cfg.hash_iters, reset=True) if a.full else (reset_state(a.stock or cfg.drop_stock) or {"reset": "state"}))
