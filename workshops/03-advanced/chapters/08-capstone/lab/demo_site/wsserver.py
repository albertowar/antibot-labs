"""
Capstone — a small WebSocket endpoint for the price-update stream (W3 Ch2)

The store pushes live price/stock updates over a WebSocket. That is a genuine
feature and a genuine abuse surface: attacks/round1_api.py floods it to exhaust
per-connection state, and at L5 the server meters each connection with the
token bucket in defenses/ws_ratelimit.py.

Why a separate asyncio server on its own port instead of upgrading through the
lab's JA4 TLS edge: the edge is a threaded WSGI server that terminates TLS and
speaks http/1.1 only, and bolting a WebSocket upgrade onto it would teach
plumbing, not detection. In production the WebSocket terminates at the same edge
as HTTP; here it runs beside it on ws://127.0.0.1:<PORT+1>, bound to localhost.
It starts in a daemon thread from app.py and never blocks the store.
"""

import asyncio
import json
import os
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
import sys
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "defenses"))
from ws_ratelimit import TokenBucket  # noqa: E402

FLOOD_KEY = "ws:flood"


async def _handler(ws, level, store):
    bucket = TokenBucket(capacity=20, refill_per_s=5.0)
    await ws.send(json.dumps({"type": "hello", "sku": "lab-runner-9", "metered": level >= 5}))
    try:
        async for _ in ws:
            if level >= 5 and not bucket.allow():
                if store is not None:
                    store.incr(FLOOD_KEY)
                await ws.close(code=1008, reason="message rate limit exceeded")
                return
            await ws.send(json.dumps({"type": "price", "sku": "lab-runner-9", "price": 220}))
    except Exception:
        return


def start(level, store, port):
    """Launch the WebSocket server in a daemon thread. Returns the thread (or None
    if the websockets package is missing — the HTTP lab still works without it)."""
    try:
        import websockets  # noqa: F401
    except ImportError:
        print(" ! websockets not installed: the WS round is skipped (pip install websockets)")
        return None

    def run():
        import websockets
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def main():
            async with websockets.serve(lambda ws: _handler(ws, level, store), "127.0.0.1", port):
                await asyncio.Future()
        try:
            loop.run_until_complete(main())
        except Exception as exc:
            print(f" ! WS server stopped: {exc}")

    t = threading.Thread(target=run, name="ws-server", daemon=True)
    t.start()
    print(f" * Price-update WebSocket on ws://127.0.0.1:{port}  (metered at DEFENSE_LEVEL>=5)")
    return t
