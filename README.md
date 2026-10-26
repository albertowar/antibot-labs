# Antibot Workshop Labs

The hands-on labs of a four-workshop training series on bot defense. Every chapter is built as rounds of **attack, then defend, then attack again**: each defense is followed by the attack that beats it, and each attack by the defense that catches it. Students play both sides against a local demo e-commerce store, Kestrel Outfitters (Flask + Redis + PostgreSQL), shared by the whole series: every lab starts as a copy of its workshop's starter (`workshops/<NN>/starter/`) and the store's contract is `workshops/STORE_CONTRACT.md`.

The chapters' content docs, the slide decks, the onboarding decks and the curriculum tracker live in the companion repo, [antibot-workshop-slides](https://github.com/albertowar/antibot-workshop-slides). Both repos use the same chapter paths: `workshops/<NN-workshop>/chapters/<NN-slug>/` holds `chapter_NN_content.md` and `slides.md` there and `lab/` here.

| Workshop | Folder | Focus |
|---|---|---|
| W1 Initiation | `workshops/01-initiation/` | HTTP-level foundations: rate limiting, IP reputation, headers, sessions, CAPTCHAs, proof of work, honeypots |
| W2 Proficient | `workshops/02-proficient/` | Browser automation, JS challenges, behaviour, fingerprinting, TLS, account takeover, ML |
| W3 Advanced | `workshops/03-advanced/` | Mobile attestation, APIs/GraphQL/WebSockets, streaming detection, risk-based authentication, session trust, ATO investigation, supply chain, raffles, ops |
| W4 AI-Era Bots | `workshops/04-ai-era-bots/` | AI crawlers, verified bot identity, agents, LLM-powered abuse, AI social engineering, agentic reverse engineering |

```
W1 Initiation ──► W2 Proficient ──┬──► W3 Advanced      (APIs, mobile, scale, ops)
                                  └──► W4 AI-Era Bots   (can run alongside or instead of W3)
```

W3 and W4 depend only on W1 and W2, never on each other. All hands-on work uses free and open-source tools; commercial products are discussed conceptually, in the chapter docs.

## Repo layout

```
PREWORK.md                    student setup: toolchain, venv, start the store, smoke test, rules of engagement
workshops/STORE_CONTRACT.md   the demo store contract: routes, headers, env, seeds, hook points
workshops/<NN-workshop>/starter/   that workshop's starting state of the store (copied by every lab)
workshops/<NN-workshop>/starter.manifest.json   the W2-W4 baselines (built, never hand-edited)
workshops/<NN-workshop>/chapters/<NN-slug>/lab/
  attacks/ defenses/ demo_site/ tools/ solutions/ data/ README.md
scripts/labnet.py             the localhost guard every lab vendors
scripts/check_labs.py         lab conventions (guard, loopback binds, solutions layout, README sections)
scripts/build_starter.py      build the W2-W4 starters (skeleton + manifest); starter_check.py reports drift
scripts/lab_diff.py           a lab's delta from its starter (writes the README's "Starts from" block)
scripts/new_lab.py            start a lab from its workshop's starter
scripts/code_diff.py          which labs changed in code since a ref (drives make verify-changed)
scripts/audit_deps.py         every lab's pins against the AGENTS.md baseline
scripts/check_links.py        repo paths named in Markdown exist (shared with the slides repo)
```

## Prerequisites

Students: follow [`PREWORK.md`](PREWORK.md) (Python 3.12, one venv per chapter, start the store, smoke test). In short:

- **Python 3.12+**, one virtualenv per chapter's `lab/` folder (see below). Every lab pins the same dependency baseline (see `AGENTS.md`), and the newest pins need 3.12.
- **Node 24 LTS (24.15 or later)** and npm, for the W2 Ch4 lab only.
- **Docker** is optional. The starter store runs on SQLite plus an in-process Redis by default, and every lab that uses Redis or PostgreSQL documents a no-Docker fallback. `docker compose up -d --wait` in any starter or lab gives the production-shaped stack (`redis:8.10.2-alpine`, `postgres:18.6-alpine`).

## Running a lab

Each chapter's `lab/README.md` is the authoritative guide and starts with `Starts from: workshops/<NN>/starter/`. The shared shape (see `workshops/STORE_CONTRACT.md` §5):

```bash
cd workshops/01-initiation/chapters/04-headers-user-agent-and-client-hints/lab
python3.12 -m venv .venv && . .venv/bin/activate  # one venv per chapter; Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/doctor.py                            # READY?
docker compose up -d --wait                       # optional: Redis + PostgreSQL instead of the defaults

python demo_site/app.py                           # start the store (level 0)
python tools/checkpoint.py --round 1              # set level 1, run the attack and the 40 shoppers, score both sides
python tools/checkpoint.py --round 1 --catch-up   # fell behind: install solutions/round1/ first (no restart)
```

**One venv per chapter.** Create the virtualenv inside the chapter's `lab/` folder and do not share it between chapters. The labs pin one dependency baseline, but two of them (W2 Ch9 and W3 Ch12) need `playwright==1.62.0` because Camoufox 0.5.8 requires `playwright<1.63`, so a shared venv will break one lab or the other. `.venv` is gitignored.

**Faster installs with uv (optional).** Because every chapter gets its own venv, installs add up. If you have [uv](https://docs.astral.sh/uv/) installed, `uv venv -p 3.12 .venv && uv pip install -r requirements.txt` is a drop-in replacement for the two lines above: its shared wheel cache makes every venv after the first take seconds and hardlinks packages instead of copying them. The `python -m venv` + pip commands in the lab READMEs remain the no-extra-tools default.

Labs are organised in rounds. Each round turns on one more defense, runs the attack that was working against the previous level, and measures both what the defense catches and what it costs real users. Checkpoints let students catch up and give an expected-results table to self-check against.

## Maintaining the labs

```bash
make check                                  # conventions, Markdown paths, starter drift (stdlib only; CI runs the same)
make verify LAB=workshops/01-initiation/chapters/02-http-attacks-and-rate-limiting/lab   # a lab's exit criteria
make verify-changed                         # the above for every lab whose code changed since REF (default HEAD)
make audit-deps                             # pins vs the AGENTS.md baseline, stale "Pins verified" headers
make build-starters                         # rebuild the W2-W4 starters from their manifests
make clean-venvs CONFIRM=1                  # delete every lab venv (uv rebuilds them fast)
```

`scripts/check_links.py` also resolves paths that live in the slides repo when a checkout of it sits next to this one (`ANTIBOT_SIBLING_ROOT`, default `../antibot-workshop-slides`); without one it warns and skips them.

## Ethics

Every lab runs only against infrastructure you own: localhost or local containers. Never point the attack scripts at third-party sites, and never route lab traffic through public proxy lists or other people's infrastructure. Every attack script and lab tool enforces this in code through the lab's `labnet.py` (a vendored copy of `scripts/labnet.py`), which refuses any target that is not loopback. `make check` (`scripts/check_labs.py`) verifies that, the loopback binds of every demo store, the solutions layout and the "Rules of engagement" section of every lab README.

## Where things are tracked

- `table_of_contents.md` in the slides repo: the curriculum, per-chapter status of content, slides and lab, and the Progress table. Update its Lab column when you finish a lab.
- `TODO.md`: the lab backlog. `DECISIONS.md`: settled choices about the store, the starters and the lab conventions.
- `AGENTS.md`: conventions for AI coding agents working on this repo (demo store, lab shape, dependency baseline, what crosses to the slides repo).
