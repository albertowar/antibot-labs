# AGENTS.md

Guidance for AI coding agents working on the Antibot Workshop labs.

## Persona

You are a **principal security engineer who specializes in antibot defenses**. You are helping to build the hands-on labs of a training workshop. You know the field from both sides: how bots work (scrapers, credential stuffers, scalpers, click fraud) and how production defenses detect them and make them more expensive. Write code and docstrings as an experienced practitioner teaching other engineers. Be technically precise and honest about trade-offs. That includes false positives and the cost to real users. Do not oversell any single control.

## What this repo is

This repo holds the **labs** of the Antibot Workshop Series: one demo store, four per-workshop starters, and one `lab/` per chapter. The series' other half (the chapter content docs, the Slidev decks, the theme, the onboarding decks, the pitch decks, the university delivery, the curriculum tracker and the review books) lives in the **slides repo**, `~/github/antibot-workshop-slides` (`github.com/albertowar/antibot-workshop-slides`). The two repos were one until 2026-10-26 and keep the same chapter paths: `workshops/<NN-workshop>/chapters/<NN-slug>/` holds `chapter_NN_content.md` and `slides.md` over there and `lab/` over here.

| Workshop | Folder | Focus |
|---|---|---|
| W1 Initiation | `workshops/01-initiation/` | HTTP-level foundations: rate limiting, IP reputation, headers, sessions, CAPTCHAs, PoW, honeypots |
| W2 Proficient | `workshops/02-proficient/` | Browser automation, JS challenges, behavior, fingerprinting, TLS, ATO, ML |
| W3 Advanced | `workshops/03-advanced/` | Mobile, APIs/GraphQL/WebSockets, streaming detection, risk-based authentication, session trust and sensitive actions, ATO investigation in audit logs, supply chain, raffles and fair allocation, ops |
| W4 AI-Era Bots | `workshops/04-ai-era-bots/` | AI crawlers, verified bot identity, agents, LLM-powered abuse, AI-driven social engineering and romance scams, agentic reverse engineering of client-side defenses |

Chapters are numbered within each workshop, starting at 0. Chapter 0 and W1 Ch1 have no lab. A reference to a chapter in another workshop uses the form "W2 Ch4" (never "Workshop 2, Chapter 4", "W2 Ch.4" or a bare "Chapter 4"). A reference inside the same workshop is a bare "Chapter 4".

### The slides repo, and what crosses between the two

- **Curriculum and status live over there.** `table_of_contents.md` in the slides repo is the source of truth for the curriculum and tracks each chapter's content doc, slides and lab (its Lab column: ✅ 🟡 ⬜ —, with a Notes column that quotes lab facts such as the contract version and the verify result). When you finish or substantially change a lab, update that row and the Progress table there in the same piece of work. This is the one cross-repo chore this split accepts.
- **A chapter's lab is taught by its doc and deck.** The content doc's `## N.y Lab:` section and the deck's round lessons and "Your turn: run the lab" lesson quote the README's round names, checkpoint commands and expected-results table. When a lab's rounds, commands or results change, the doc, the deck and the workshop's Chapter 0 tour over there must change too; say so in your summary if you cannot do it yourself.
- **Naming the other repo.** A lab file refers to its chapter's doc or deck by its repo-rooted path followed by "(slides repo)": `workshops/02-proficient/chapters/04-javascript-challenges-and-obfuscation/chapter_04_content.md` (slides repo). Never by a relative `../chapter_NN_content.md`: it does not exist here. Student setup is this repo's `PREWORK.md`; the onboarding decks that narrate it are `onboarding/setup/`, `onboarding/demo-store/` and `onboarding/lab-harness/` in the slides repo.
- **Sibling checkout.** `scripts/check_links.py` resolves a repo-rooted path first against this repo, then against the sibling checkout named by `ANTIBOT_SIBLING_ROOT` (default `../antibot-workshop-slides`); when the sibling is absent it prints one warning and skips those paths. The script is byte-identical in both repos, like `labnet.py`; edit it in one and copy it to the other.
- **Sourced claims.** A number, a version, a date or a "study shows" in a README or a docstring needs a source. The chapter's `## References` list lives in its content doc in the slides repo; a lab README cites inline (author, title, year, URL) or points at the doc's `§N.x`. Mark a figure the lab measured as measured, not as a citation. Never invent a source.

## Work tracking (`TODO.md`)

- The root `TODO.md` is the lab backlog: what is still wrong or missing in a lab, a starter, the contract or the scripts. Doc and deck findings live in the slides repo's `TODO.md`.
- The five chapter-level residue lists (W2 Ch1, W2 Ch8, W3 Ch5, W3 Ch6, W3 Ch9) sit next to the chapter's doc and deck in the slides repo (`workshops/<NN>/chapters/<slug>/TODO.md`) because they mix doc and lab items; this file links to them. A chapter folder here may carry a `lab/TODO.md` for lab-only residue (W4 Ch8 does).
- When you address an item, delete it from the relevant `TODO.md` in the same change. Do not tick it and leave it in place; the files list only open work. If you address an item partially, rewrite it to describe what remains.
- Settled maintainer choices live in `DECISIONS.md`, not `TODO.md`. Lines marked **Decision** there record a choice made on purpose; follow them and do not reopen the question. When a `TODO.md` item is closed by a deliberate choice rather than a fix, move the choice to `DECISIONS.md` and leave a one-line pointer on whatever still references it.
- Addressing a TODO item does not replace the `table_of_contents.md` update in the slides repo. Do both.

## Curriculum principles

These are set in the slides repo's `table_of_contents.md` and are non-negotiable on the lab side:

- **One spine, four depths.** Eight strands (client identity, cost imposition, behavior and deception, sessions/accounts/delegated trust, client-side code, decisioning, operating and measuring, landscape/law/ethics); each workshop asks the same questions with a stronger attacker. A new lab is placed by its chapter's strand, which the chapter doc declares.
- **Attack/defend back-and-forth.** "Every defense is followed by the attack that beats it, and every attack by the defense that catches it." Structure labs as rounds.
- **Free and open-source tools only** for hands-on work. Commercial products are discussed conceptually, in the docs.
- **One demo e-commerce site**, Kestrel Outfitters (Flask + Redis + PostgreSQL), runs every lab in the series. Its contract is `workshops/STORE_CONTRACT.md`; each workshop ships its own starter in `workshops/<NN>/starter/`, and every chapter of that workshop starts from it (see "Demo store" below).
- **Ethics first.** Every lab runs only against infrastructure the students own, such as localhost or local containers. Never target third-party sites. Never route lab traffic through public proxy lists or other people's infrastructure.
- **Self-paced first.** The series is built for self-paced online study. Every lab round is self-checking, and nothing depends on a room, an instructor or a partner; a peer exercise (pairs, team-vs-team) always ships a solo variant with a reference answer.
- **Audience.** W1 is for web developers and junior security engineers with basic Python. W1 attackers use `requests`/`httpx` and basic Playwright.

## Demo store

- `workshops/STORE_CONTRACT.md` is binding: routes, JSON shapes, lab routes, `X-Lab-*` headers, env vars, the simulated edge (`X-Lab-Client-IP` only, `X-Lab-Actor` is ground truth no defense may read), seed data, DOM selectors, hook points.
- **Starters.** `workshops/01-initiation/starter/` is the skeleton, written by hand. The W2, W3 and W4 starters are the skeleton plus that workshop's baseline, declared in `workshops/<NN>/starter.manifest.json` and built by `scripts/build_starter.py --workshop N` (`--all`), never edited by hand; `scripts/starter_check.py` reports drift. Every baseline is empty by decision (`DECISIONS.md`): each workshop runs on its own, no starter is a previous capstone's end state, and a chapter that needs an earlier control at its Round 0 (W1's header rules, say) adds it in its own lab.
- **Copy, don't import.** A lab copies its workshop's starter (`labnet.py`, `demo_site/`, `defenses/`, `tools/`, `data/`, compose, requirements) and adds: `defenses/<name>.py` checks wired into `defenses/ladder.py` (round N = `LADDER[N]`), `demo_site/ext/<name>.py` modules (routes, slots, challenge types, telemetry kinds, enrichers), `attacks/roundN_*.py`, `tools/personas_<ch>.py`, `solutions/roundN/`. A lab may edit `ladder.py`, `policy.py`, `tools/checkpoint.py` and templates; editing any other starter file is a contract bump, not a chapter change.
- **README rule.** Every lab README starts with `Starts from: workshops/<NN>/starter/ (contract X.Y). Adds: …` (`scripts/lab_diff.py <lab> --write-readme` generates the block). Where a lab deliberately works on a slice of the store (W3 Ch8), the README says so.
- **Two lab styles; keep the chapter's.** *Wire-it*: defenses ship as stubs with `TODO (Round N)` and full versions in `solutions/roundN/`; `--catch-up` installs them. *Pre-written*: defenses ship complete and students read them and switch levels; `solutions/roundN/` then holds only the per-round `ladder.py`/`policy.py`. The README says which.
- **Start a lab** with `python scripts/new_lab.py <chapter folder>` (copies the starter without `.venv`, `instance/`, `__pycache__`). Verify with `python tools/verify.py`: it binds a free port, so parallel agents do not collide; never `pkill -f demo_site/app.py` (it matches your own shell).
- **Exit criteria** for a lab: `python tools/verify.py --write-readme` (one process: every round judged, each followed by its `--level N-1` "before" run, then the README's before/after table is regenerated between its `results:start/end` markers — generated, never hand-edited or copied from an older lab; review the `git diff`), `python tools/verify.py --smoke`, and `python scripts/check_labs.py <lab>`. `make verify LAB=<lab>` runs the two verify calls. Before runs are report-only and never affect the exit code: an earlier level may legitimately hurt a persona the round fixes — quote that in the README rather than chasing a PASS.
- **Retired names** (do not reintroduce): `/admin/*`, `/api/v0/*`, `/api/sensor`, `/api/session`, `/api/fp`, `/telemetry`, `/products/<sku>`, `/signup`, `X-Lab-Source-IP`, `X-Sim-Client-IP`, `X-Lab-Egress`, `STORE=memory`, `fakeredis://` (alias still accepted; write `memory://`). `/catalog` is not retired: it is the starter's canonical alias of `/products`.

## Chapter folder layout

```
workshops/<NN-workshop>/chapters/<NN-kebab-slug>/
  lab/                    # the chapter's hands-on material (the doc and deck are at the same path in the slides repo)
```

### Lab (`lab/`)
- Start as a copy of `workshops/<NN>/starter/`: `labnet.py`, `demo_site/`, `defenses/`, `tools/`, `data/`, `docker-compose.yml`, `requirements*.txt`, `.env.example`, `.gitignore`; add `attacks/`, `solutions/roundN/` and a `README.md` (see "Demo store").
- Organize by rounds. Each round has a defense step and an attack step, `tools/checkpoint.py --round N` (with `--catch-up`) so students can catch up, and a `## Expected results (self-check)` table generated by `--all --markdown` that a learner working alone compares against. Checkpoints print PASS/FAIL against explicit thresholds, not only a view. A step that depends on the learner's own browser or on other people ships a reference capture or answer key to compare against.
- Measure defender cost as well as attacker success: the starter's `tools/population.py` shoppers run next to every attack, and the scoreboard reports shoppers hurt next to bots stopped, plus `Server-Timing` gate cost.
- **Pacing.** Shoppers sleep like humans, which is most of a round's wall time. A lab may divide every shopper pause by a `SPEEDUP` constant in its `tools/personas_<ch>.py` (W1 Ch2/Ch3 use 5.0); it applies identically to the student checkpoint and `verify.py`, so regenerate the expected-results tables under the same setting. Do not speed a round up by running its attacks in parallel instead: attacks share one store, and global defenses (honeypots, adaptive PoW, telemetry thresholds) make interleaved results non-deterministic. **Decision:** attacks within a round stay serial.
- Code style: plain Python scripts with a `__main__` guard, docstrings that explain trade-offs, every attack imports `tools/labclient.py` (which runs the `labnet` guard on import), and ends by printing one JSON line.
- **Localhost guard.** Every lab with network code carries `labnet.py` at the lab root, a byte-identical copy of `scripts/labnet.py`. Attack scripts and tools get the store URL from `labnet.target("DEMO_URL", "<default>")` and never read `DEMO_URL` themselves; side services (`PROVIDER_URL`, `COLLECTOR_URL`, `MOCK_URL`, `LLM_URL`, `OLLAMA_URL`, …) go through `labnet.require_local()` or `require_local_env()`. Lab helpers (`attacks/_common.py`, `tools/lab.py`, `tools/labclient.py`, …) may wrap it but not re-implement it; on the starter chain that wrapper is `tools/labclient.py` (`LabClient`, world pools), which every attack imports. To change the guard, edit `scripts/labnet.py` and copy it into every lab and starter.
- **Loopback only.** `app.run(...)` always passes `host="127.0.0.1"`, compose `ports:` are `127.0.0.1:<host>:<container>`, and the Werkzeug debugger stays off unless `LAB_DEBUG=1`. An outbound call to the real internet is allowed only as a documented opt-in that is off by default (today: W2 Ch3's checksummed setup download, W3 Ch4's `HIBP_LIVE=1`, W4 Ch2's `tools/verify_real.py`); add it to the allowlist in `scripts/check_labs.py` with the reason.
- **Solutions and catch-up.** Reference solutions live at `lab/solutions/roundN/<path relative to lab>`, each round holding only the files it changes, in their finished state. `tools/checkpoint.py --round N --catch-up` installs rounds 1..N (one `.bak` per student file; unmigrated labs use `labnet.catch_up()`, starter-chain labs install the files each `Round(solutions=…)` names) and `--restore` puts the student files back with `labnet.restore()`. A student stub must never be byte-identical to its solution.
- **Level-style labs** are an accepted alternative to stub + solutions: every defense is pre-written and students switch `DEFENSE_LEVEL` (W1 Ch4/6, W2 Ch2/4/5/8, W3 Ch3/8/10). Their README says catching up means restarting at the round's level. On the starter chain this is the *pre-written* style (see "Demo store").
- **Rules of engagement.** Every lab README has a `## Rules of engagement` section near the top: the `labnet.py` guard, what is synthetic and simulated in that lab, and an explicit **Outbound network** line.
- Run `make check` before committing a lab; it enforces the lab conventions (`scripts/check_labs.py`: the guard, the loopback binds, the solutions layout, the README section), Markdown links and starter drift.
- **Analyst-side labs** (W3 Ch7, W4 Ch6) are an accepted alternative shape: no `demo_site/` or `attacks/`; a deterministic generator in `tools/` writes a gitignored dataset, students work in `notebooks/`, `tools/score.py` is the checkpoint (recall per campaign, FP per cohort vs the 2% budget, precision@k), reference detectors live in `solutions/`, and a `tests/` script asserts the tier-integrity claims the README table rests on. Commit notebooks with outputs stripped (`nbstripout`).
- **Offline policy labs** (W3 Ch11, W4 Ch10) are stdlib-only: a seeded log, a policy JSON, exposure notes and a keyword-scored paper round, with no store and no guard (`DECISIONS.md`).

## Dependency baseline

Every lab pins the same versions. "Latest release without known vulnerabilities" is the rule; refresh the table by querying PyPI/Docker Hub, running `pip-audit -r requirements.txt` in a scratch venv, then re-running every lab's checkpoints. `make audit-deps` reports the current state (pins vs this table, stale "Pins verified" headers, pip-audit when installed); the refresh itself stays manual. A lab may deviate only with a comment in its `requirements.txt` naming the constraint (today: two, both listed in the table).

| Component | Pin | Notes |
|---|---|---|
| Python | 3.12+ | one floor for every lab, stdlib-only labs included (numpy 2.5 needs 3.12) |
| Node | 24 LTS, 24.15+ | the W2 Ch4 lab (`engines.node` in its `package.json`); the slides repo pins the same for Slidev |
| Flask / Flask-SQLAlchemy / Flask-Session | 3.1.3 / 3.1.1 / 0.8.0 | |
| SQLAlchemy / psycopg[binary] | 2.1.4 / 3.3.6 | |
| redis / fakeredis | 8.1.0 / 2.39.0 | `fakeredis[lua]` is the baseline spelling since contract 1.4 (the starter's token bucket is a Lua script); add `[probabilistic]` where a lab needs it; `>=2.39` is required by the redis 8 client (RESP3 `HELLO`) |
| requests / httpx | 2.34.2 / 0.28.1 | |
| cryptography / PyJWT / pyotp | 50.0.2 / 2.15.1 / 2.10.0 | |
| playwright / patchright | 1.63.0 / 1.63.0 | bundles Chromium 153. **Exception:** `playwright==1.62.0` in W2 Ch9 and W3 Ch12, because `camoufox==0.5.8` requires `playwright<1.63`. This is why each chapter gets its own venv. |
| camoufox / playwright-stealth / selenium | 0.5.8 / 2.0.3 / 4.51.0 | |
| curl_cffi / impit | 0.16.3 / 0.14.1 | |
| numpy / scipy / scikit-learn / pandas / pyarrow / lightgbm / imbalanced-learn | 2.5.4 / 1.18.1 / 1.9.1 / 3.0.6 / 26.0.0 / 4.7.0 / 0.14.2 | pin scipy only where a lab imports it directly (W1 Ch5's OCR solver); otherwise scikit-learn pulls it in |
| websockets / flask-sock / simple-websocket | 17.2 / 0.7.0 / 1.1.0 | |
| strawberry-graphql / graphql-core | 0.333.0 / 3.3.0 | |
| Pillow / user-agents / dnspython / prometheus-client / ollama | 12.3.0 / 2.2.0 / 2.9.0 / 0.26.0 / 0.6.3 | |
| mitmproxy | 12.2.3 | W3 Ch1 live demo only, in a separate `requirements-mitmproxy.txt`. **Exception:** it requires `cryptography<=48.1`, so that file pins `cryptography==48.0.1` and is installed after the baseline file. It also caps tornado at 6.5.5 (three open GHSA advisories in the HTTP server, used only by mitmweb); the demo uses `mitmdump`/console, never mitmweb. |
| `redis` image | `redis:8.10.2-alpine` | |
| `postgres` image | `postgres:18.6-alpine` | mount the volume at `/var/lib/postgresql` (the 18 image moved `PGDATA` under it) |
| `prom/prometheus` / `grafana/grafana` | `v3.15.0` / `13.2.3` | W3 Ch10 `monitoring` and W3 Ch12 `prod` profiles |
| `redpandadata/redpanda` | `v26.2.4` | W3 Ch12 `prod` profile |

Rules that go with the table:

- **One venv per chapter**, created inside `lab/` as `.venv`. Lab READMEs say so on their `python -m venv` line; the root README explains why. When `uv` is available, create and fill the venv with it instead (see "Finding things without reading everything").
- `requirements.txt` starts with `# W<w> Ch<n> lab. Python 3.12+. Pins verified <Month YYYY>.` and pins exact versions (`==`).
- Prose (READMEs, docstrings) names versions at minor granularity ("Flask 3.1", "Redis 8.10", "PostgreSQL 18"); only `requirements.txt` and compose files carry patch versions.

## Tooling

- `make check` runs `scripts/check_labs.py` over every `workshops/*/starter/` and `workshops/*/chapters/*/lab/` (it discovers new labs on its own), then `scripts/check_links.py` and `scripts/starter_check.py --no-boot` (manifest drift + contract versions; `.github/workflows/checks.yml` runs the same on push/PR). `make verify LAB=<lab>` runs a lab's exit criteria; `make verify-changed` runs them for every lab `scripts/code_diff.py --labs` maps the current diff to; `make audit-deps` (`scripts/audit_deps.py`) diffs every lab's pins against the baseline table and flags stale "Pins verified" headers; `make clean-venvs CONFIRM=1` deletes the lab venvs (uv rebuilds them near-instantly); `make build-starters` rebuilds the W2–W4 starters from their manifests.
- `PREWORK.md` at the root is the student setup walkthrough (toolchain, venv, start the store, smoke test, rules of engagement); a lab README keeps only its own extra installs (e.g. a browser) as a delta on it. The onboarding decks that narrate the same steps, and the store screenshots they show, are in the slides repo (`scripts/capture_store_shots.py` there boots this repo's W1 starter through `ANTIBOT_SIBLING_ROOT`).

## Finding things without reading everything

- `TODO.md` and `workshops/STORE_CONTRACT.md` have stable per-section headings. To check one chapter's residue or one contract section, grep for the heading, read only that section, and edit in place; neither needs an end-to-end read for a routine update.
- Thirty-nine labs each carry a full copy of the store, so a repo-wide search for a store symbol returns dozens of near-identical hits. Scope searches to the chapter's `lab/`, or to `workshops/<NN>/starter/` when you mean the canonical copy. `scripts/labnet.py` is the one editable guard; every other `labnet.py` is a vendored copy.
- Create lab venvs with `uv` when it is installed (`uv venv -p 3.12 .venv && uv pip install -r requirements.txt`): its shared wheel cache makes every venv after the first near-instant. Student-facing docs keep the stdlib `python -m venv` + pip commands as the portable default; the root README names uv as the fast path.

## Verifying changes

Verify what your change can break, with the cheapest check that would fail. A full lab run takes minutes per lab (a W1 lab's `--all --with-before` is ~2–3 min, dominated by the shopper population's human-paced sleeps); it tells you nothing about a README edit.

| You changed | Run | Not needed |
|---|---|---|
| Prose: READMEs, docstrings, the contract's wording | a read-through; `python scripts/check_links.py` if you named files or paths | lab runs |
| Python in a lab or starter | `python scripts/code_diff.py [--base <ref>]` lists the files that changed in code (docstrings and comments ignored); for those labs, `tools/verify.py --smoke` plus the rounds that use the changed module | rounds and labs whose code did not change |
| Defense, attack, checkpoint or starter logic | the lab exit criteria in "Demo store" (`verify.py --write-readme`, `--smoke`, `check_labs.py`); `make verify-changed` runs them for every lab the diff touches | |
| A starter or the contract | `python scripts/build_starter.py --all` then `python scripts/starter_check.py`; the contract version bump and changelog in `STORE_CONTRACT.md`; every lab README's `Starts from:` line | |
| A rename or move (chapter, file, folder, module) | `python scripts/check_links.py`, `make check`, a grep for the old name, `code_diff.py` for imports; the same rename in the slides repo | |

Bulk edits across many files (a renumber, a rename, a terminology change):

1. Write the edit as a script in your scratchpad. Do one pass per file with a single substitution callback, so nothing is replaced twice.
2. Dry-run the script and have it log every replacement with its rule and some surrounding context. Review the log rule by rule before you apply anything. The risky rules are the ones that match bare numbers, bare "Chapter N" and paths shared between workshops.
3. After applying, audit the diff mechanically. With `git diff --word-diff=porcelain`, every change should match the intended transformation; list the ones that don't and check each by hand. Then grep for the old form to find misses. `code_diff.py` and `check_links.py` cover code and paths.

Running checks:

- Run anything longer than a minute with `run_in_background`, and size foreground timeouts to the job.
- Don't run CPU-heavy jobs side by side (two proof-of-work labs slow each other). Build and verify once, after the last edit.
- Never `pkill -f <pattern>`: the pattern also matches the shell running it, and other worktrees' processes. Kill the `$!` you started, or `pgrep` and exclude `$$`.

## Known stale content

- The W4 Ch8 lab stays 🟡: rounds 3–4 don't reproduce from a fresh environment (P1 in `workshops/04-ai-era-bots/chapters/08-adversarial-ml-and-synthetic-data/lab/TODO.md`; its doc and deck teach those rounds by design and quote the failure).
- W4 Ch7 (Agentic Reverse Engineering) has a doc and a deck but no `lab/` yet; the design is in `TODO.md`.
- The lab READMEs and the slides repo's `table_of_contents.md` Notes column quote the contract version each lab was last re-based on; contract 1.8 is current.
