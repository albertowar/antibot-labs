"""
Chapter 7, Round 0 attack: recon.

Look at the store the way a bot does. What does the signup form contain? What does robots.txt say?
Then create one account, to confirm the form works for scripts at DEFENSE_LEVEL=0.

    python attacks/round0_recon.py

Expected:   level 0: three inputs (name, email, password), one account created.
            level 1+: an extra input appears. Run this again each round and compare. At level 1 the
            recon bot fills it like any other input and the signup is silently dropped.
"""

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, LabClient, world_pool  # noqa: E402

ACTOR = "bot:r0_recon"


def run(verbose=False):
    bot = LabClient(ACTOR, ip=world_pool("cloud_vm")[0])
    robots = bot.get("/robots.txt", trapkit.headers("typed")).text
    page = bot.get("/register", trapkit.headers("link", BASE_URL + "/"))
    fields = trapkit.parse_form(page.text)
    user = f"recon-{secrets.token_hex(3)}"
    data = {f["name"]: f.get("value", "") if f.get("type") == "hidden" else trapkit.fill_value(f, user)
            for f in fields if f.get("name") and f.get("type") not in ("submit", "button")}
    reply = trapkit.follow(bot, bot.post("/register", data, trapkit.headers("post", BASE_URL + "/register")),
                           trapkit.headers("link", BASE_URL + "/register"))
    ok = trapkit.signed_up(reply)
    if verbose:
        print("robots.txt:\n  " + robots.strip().replace("\n", "\n  "))
        print("\nSignup form inputs, as the raw HTML shows them:")
        for f in fields:
            hints = ", ".join(f"{k}={v!r}" for e in [f, *f["_ancestors"]] for k, v in e.items()
                              if k in ("style", "class", "aria-hidden", "tabindex") and not k.startswith("_"))
            print(f"  name={f.get('name')!r:<16} type={f.get('type', 'text'):<9} label={f['_label']!r:<26} {hints}")
        print(f"\nSignup as {user!r}: landed on {reply.url.replace(BASE_URL, '')} ({reply.status_code}); "
              f"the bot believes it {'succeeded' if ok else 'failed'}.")
    return {"attempted": 1, "succeeded": int(ok), "inputs": len(fields)}


if __name__ == "__main__":
    print(json.dumps(run(verbose=True)))
