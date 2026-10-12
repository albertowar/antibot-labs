# Pre-work: get the store running before you start

Do this before your first chapter of any workshop. It takes about 20 minutes on a laptop with a normal connection,
and it is the only setup the series needs. The Setup deck (`onboarding/setup/slides.md`) narrates the same
steps; the Demo Store deck (`onboarding/demo-store/slides.md`) shows the shop you just started, and the Lab
Harness deck (`onboarding/lab-harness/slides.md`) shows how the labs measure attacks and defenses against it.

## 1. Install the toolchain

| Need | Version | Why |
|---|---|---|
| Python | **3.12** (3.13 fine) | every lab; `python3.12 --version` |
| Git | any | clone the repo |
| Node.js | 24 LTS | only to view the slide decks locally, and for W2 Ch2's JS toolchain |
| Docker + Compose | optional | the production-shaped stack (Redis + PostgreSQL); every lab also runs without it |

Windows: use WSL 2 (Ubuntu) and do everything inside it. macOS: `brew install python@3.12`. Linux:
`sudo apt install python3.12 python3.12-venv`.

## 2. Clone and pick your starter

```bash
git clone <this repo> antibot-workshop-slides
cd antibot-workshop-slides
```

Each workshop starts from its own copy of the store, in `workshops/<NN>/starter/`. Workshop 1 starts
from the bare skeleton; Workshop 2 from the state the W1 capstone leaves behind; Workshops 3 and 4 from
the W2 capstone's state. For the pre-work, use the starter of the workshop you are attending; the
commands are identical.

## 3. One virtualenv per lab

Each chapter's `lab/` has its own `requirements.txt` with exact pins, and some pins conflict across
chapters (W2 Ch9 needs an older Playwright). So: one venv per folder, always. The starter is the first one.

```bash
cd workshops/01-initiation/starter            # or the starter of your workshop
python3.12 -m venv .venv
. .venv/bin/activate                          # Windows (inside WSL): same command
pip install -r requirements.txt
python tools/doctor.py
```

`doctor.py` must end with `READY`. It checks the Python version, the venv, every dependency, your
Redis and database URLs, and that `DEMO_URL` points at this machine.

## 4. Start the store

```bash
python demo_site/app.py
```

Open <http://127.0.0.1:5000>. You should see Kestrel Outfitters: a hero, two drops, a catalog of 120
products. Browse, add something to the cart, check out with any card number. Log in as
`user031@example.test`; the password is printed by
`python -c "import demo_site.seed as s; print(s.password_for(31))"`.

If port 5000 is taken (macOS AirPlay often holds it): `PORT=8099 python demo_site/app.py`, and in every
other shell `export DEMO_URL=http://127.0.0.1:8099`.

## 5. Smoke test

In a second shell, same folder, venv active:

```bash
python tools/smoke.py                   # contract test: every route, header and seed count. Ends with "smoke: OK"
python tools/population.py              # 40 simulated shoppers buy something; the "hurt" column must be 0
python tools/scoreboard.py              # what the store logged about them
curl -s http://127.0.0.1:5000/whoami    # what the lab edge thinks you are
```

`tools/population.py` is the other half of every measurement in the series: a defense that stops a
shopper shows up there as a cost. Expect every persona in the `ok` column at level 0.

## 6. Optional: the Docker path

```bash
docker compose up -d --wait
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python tools/doctor.py && python demo_site/app.py
```

Same store, real Redis and PostgreSQL. Labs that teach multi-process state or persistence say when
this path matters; otherwise the default (SQLite + an in-process Redis) is enough.

## 7. Optional: a browser for the Playwright labs

```bash
pip install -r requirements-browser.txt
python -m playwright install chromium
```

Only labs whose README asks for it (W1 Ch9, most of W2, parts of W4) need this.

## 8. Rules of engagement (you agree to these before your first lab)

- Lab traffic goes to **this machine only**. `labnet.py` at the lab root refuses any other `DEMO_URL` (and any non-local
  `REDIS_URL` or `DATABASE_URL`); the store
  refuses anything that is not loopback.
- Source addresses are **rented** from `data/world.json` (documentation ranges), never invented and
  never real. No public proxy lists, no VPNs, no Tor, no other people's infrastructure.
- Only synthetic users, credentials and data. The 300 seeded accounts and their passwords exist for
  the credential-stuffing chapters; they are not real people.
- Techniques learned here are used only against systems you own or are authorised to test.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3.12: command not found` | install 3.12 (see §1); `python3 --version` must say 3.12 or newer |
| `doctor.py` says a module is missing | the venv is not active, or `pip install -r requirements.txt` was run elsewhere |
| `Address already in use` | `PORT=8099 …` and `export DEMO_URL=http://127.0.0.1:8099` |
| `421 Misdirected Request` from the store | a script sent an address outside `data/world.json`; rent one from a pool |
| `Refusing to run against …` | `DEMO_URL` is not localhost; the guard is doing its job |
| Redis `unknown command 'hello'` | an old fakeredis; `pip install -r requirements.txt` again inside the venv |
| Shoppers in the `other` column | the store was restarted mid-run, or it is not the store you think (`/whoami`) |
