"""
Chapter 6 — Shared bot plumbing for the attack scripts

A bot here already does what earlier chapters forced it to: it sends a
current Chrome User-Agent (Chapter 4) and keeps cookies (Chapter 5). Each
round's script adds only the one new trick that round is about.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import BOT_NET, client, random_ip, require_local  # noqa: E402,F401

BOT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


def bot(ip=None, actor="bot"):
    return client(ip or random_ip(BOT_NET), BOT_UA, actor)


def unlock(c):
    c.get("/promo/unlock")


def new_challenge(c):
    """Fetch a challenge. Returns (challenge_id, png_bytes) or (None, None)."""
    r = c.get("/captcha/new")
    if r.status_code != 200:
        return None, None
    data = r.json()
    return data["id"], base64.b64decode(data["image"].split(",", 1)[1])


def redeem(c, challenge_id="", answer=""):
    r = c.post("/promo/redeem", data={"captcha_id": challenge_id, "captcha": answer})
    return r.status_code, r.json()


def summary(name, attempts, successes, **extra):
    return {"name": name, "attempts": attempts, "successes": successes, **extra}
