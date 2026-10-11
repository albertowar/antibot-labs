# Kestrel Outfitters: the W1 starter (the skeleton store)

**Contract:** `workshops/STORE_CONTRACT.md` (version 1.1). **Source:** bare; this is the skeleton every
other starter derives from. **Baseline defenses:** none (`defenses/ladder.py` has an empty `LADDER[0]`).

This folder is copied, never imported, by every Workshop 1 chapter lab. Do not edit it inside a lab;
if a chapter needs something the skeleton lacks, that is a contract change (see the contract's §4).

## Boot it (under 10 minutes)

```bash
cd workshops/01-initiation/starter
python3.12 -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/doctor.py                                     # READY?
python demo_site/app.py                                    # http://127.0.0.1:5000
```

Open the store, browse, buy something, log in as `user031@example.test` (password: `python -c
"import demo_site.seed as s; print(s.password_for(31))"`). Then, in a second shell with the venv active:

```bash
python tools/smoke.py                 # the contract, as a test
python tools/population.py            # 40 shoppers; none should be hurt at level 0
python tools/scoreboard.py            # bots stopped vs shoppers hurt
python tools/checkpoint.py --round 0  # the two above, scored
curl -s localhost:5000/whoami | python -m json.tool
```

With Docker, for the production-shaped stack: `docker compose up -d --wait`, then export
`REDIS_URL=redis://127.0.0.1:6379/0` and
`DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop` before starting the store.

Port 5000 busy? `PORT=8099 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:8099` for the tools.

## What is in here

```
labnet.py       the localhost guard and catch-up helper (byte-identical copy of scripts/labnet.py; do not edit here)
demo_site/      the Flask store: app factory, models, seed, images, lab edge, gate, hooks, routes, templates, static
defenses/       the engine (pipeline, policy, context, store, decision log) and the wiring file ladder.py
tools/          labclient (the guarded lab client), population (shoppers), checkpoint, verify, smoke, doctor, build_world
attacks/        empty; a chapter adds roundN_*.py
data/           world.json (simulated internet), feeds/ (built from it), wordlists/
```

## Rules of engagement

- **Local only, enforced in code.** `tools/labclient.py` asks `labnet.py` at the lab root for `DEMO_URL` and
  refuses anything that is not this machine (side-service URLs such as `REDIS_URL` and `DATABASE_URL` too),
  and the lab edge accepts the lab headers only from loopback.
- Source addresses are rented from `data/world.json`, never invented, never real. No public proxy lists, no
  third-party sites, no real users or credentials.
- **Outbound network:** none while the store runs. Only setup needs the internet: installing packages, browsers
  and container images.
