"""
W4 Ch7 — The analyst's tables, in the store's own database

The chapter's offline pipeline needs four tables next to the store's own:

  requests   one event per response the store served, written by the ext's
             hooks.on_response observer (demo_site/ext/llm_log.py): path, status,
             and every header the client chose to send (User-Agent, Referer,
             Accept-Language). Assets included: an ungated /static or /img fetch
             builds no Ctx, but the observer still sees it.
  logins     one row per login ATTEMPT (hooks.on_action("login"), contract 1.7),
             success or failure: the submitted account name is attacker text too.
  verdicts   what the triage pipeline (heuristic or LLM) said about a session
  rule_hits  rules that matched at checkout, in shadow or enforce mode

They live in the same DATABASE_URL as the store (ext tables are the contract's
pattern; POST /lab/reset clears them through the ext's on_reset), so every tool
that runs next to the store reads the same file or server.

Client-controlled columns are Text, not String(200): the Round 3 flood sends
multi-kilobyte headers, and a column that truncates them would hide the attack.
The ext caps each stored value at MAX_FIELD_BYTES so the database itself is not
the resource the flood eats.

Timestamps are real Unix seconds. Every *duration* the session summary uses is
divided by LAB_TIME_SCALE (shared with tools/personas_llm.py), so the simulators
can compress a shopping session of minutes into about a second.
"""

import os

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, create_engine

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Same default as demo_site/config.py, so tools run from lab/ find the store's file.
DEFAULT_DB = f"sqlite:///{os.path.join(LAB, 'instance', 'shop.db')}"
LAB_TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "0.02"))
MAX_FIELD_BYTES = 8192

metadata = MetaData()

requests_t = Table(
    "llm_requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(64), index=True),
    Column("ts", Float, index=True),
    Column("method", String(8)),
    Column("path", Text),
    Column("status", Integer),
    Column("ip", String(45)),
    Column("asn", String(80)),          # what the simulated edge resolved (ctx.edge)
    Column("country", String(8)),
    Column("ua", Text),
    Column("referer", Text),
    Column("accept_language", Text),
    Column("is_asset", Integer),
    Column("bytes_out", Integer),
)

logins_t = Table(
    "llm_logins", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(64), index=True),
    Column("ts", Float),
    Column("account", Text),            # as submitted: attacker-controlled text
    Column("user_id", Integer),         # the matched store user, when the login succeeded
    Column("ok", Integer),
)

verdicts_t = Table(
    "llm_verdicts", metadata,
    Column("id", Integer, primary_key=True),
    Column("run_id", String(60), index=True),   # which triage run produced it
    Column("tag", String(40)),                  # free label, e.g. "r1-raw", "r2-hardened"
    Column("sid", String(64), index=True),
    Column("ts", Float),
    Column("backend", String(12)),              # heuristic | mock | ollama
    Column("model", String(60)),
    Column("mode", String(12)),                 # session | cluster | starved
    Column("label", String(8)),                 # human | bot | unsure
    Column("confidence", Float),
    Column("reasons", Text),                    # JSON list
    Column("proposed_rule", Text),              # JSON or null (display only, never enforced)
    Column("valid", Integer),
    Column("flags", Text),                      # JSON list of validator / sanitizer flags
    Column("prompt_tokens", Integer),
    Column("completion_tokens", Integer),
    Column("est", Integer),                     # 1 = token counts are chars/4 estimates
    Column("latency_ms", Float),
    Column("cluster_id", String(64)),
)

rule_hits_t = Table(
    "llm_rule_hits", metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Float),
    Column("sid", String(64), index=True),
    Column("rule_id", String(20)),
    Column("mode", String(8)),                  # shadow | enforce
)

_engine = None


def make_engine(url=None):
    """An engine on the store's database (tools side; the ext uses the app's own)."""
    global _engine
    if url is None and _engine is not None:
        return _engine
    url = url or os.environ.get("DATABASE_URL", DEFAULT_DB)
    if url.startswith("sqlite"):
        eng = create_engine(url, connect_args={"timeout": 30, "check_same_thread": False})

        from sqlalchemy import event

        @event.listens_for(eng, "connect")
        def _pragmas(conn, _):
            # WAL lets the triage tools read while the store writes events.
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
    else:
        eng = create_engine(url, pool_size=10, max_overflow=10)
    if _engine is None:
        _engine = eng
    return eng


def create_tables(engine):
    metadata.create_all(engine)


def clear(engine):
    """Empty the four tables (the ext's on_reset calls this)."""
    with engine.begin() as conn:
        for t in (requests_t, logins_t, verdicts_t, rule_hits_t):
            conn.execute(t.delete())
