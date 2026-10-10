"""Shared datastore for the W2 Ch6 account-takeover demo store.

Two backends, chosen by environment variables, so the lab runs on a bare laptop
*and* in a production-shaped stack:

  * Redis       -> real server when REDIS_URL is set, otherwise an in-process
                   ``fakeredis`` instance. The demo site is the only process that
                   touches Redis, so fakeredis (which lives only in this process)
                   is enough; attackers and the simulator talk to us over HTTP.
  * SQL (users + the login-event log) -> PostgreSQL when DATABASE_URL is set,
                   otherwise a local SQLite file. Both the app and the tools read
                   the event log, so it must be a *shared* store; SQLite is a file
                   on disk, which is why the log lives here and not in Redis.

Nothing here is bot-detection logic. It is plumbing the defense modules build on.
"""

from __future__ import annotations

import os
import time

from flask_sqlalchemy import SQLAlchemy

# --- Redis (velocity counters, device/location history, challenge state) --------

def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set.

    Trade-off: fakeredis keeps the lab dependency-free, but its state is per
    process and vanishes on restart. That is exactly what we want between rounds
    (each round restarts the server with a clean slate), and the attack/legit
    tooling never needs Redis because it drives the app over HTTP.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        import redis  # imported lazily so the lab installs without a server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


# --- SQL (users and the append-only login-event log) ---------------------------

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(32), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # TOTP secret, set for the subset of users who enrolled a second factor.
    totp_secret = db.Column(db.String(64), nullable=True)
    # Whether this account's password appears in the local breach corpus. Stored
    # at seed time so the demo does not have to hash-and-range-check on every read.
    password_breached = db.Column(db.Boolean, default=False, nullable=False)


class LoginEvent(db.Model):
    """One row per security-relevant request.

    ``actor`` is lab-only ground truth: the attack scripts and the legitimate
    simulator stamp every request with ``X-Lab-Actor`` so the scoreboard can tell
    an account takeover from a false positive. A real login endpoint has no such
    oracle; it is here only to measure both sides of the arms race.
    """

    __tablename__ = "login_events"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False)
    actor = db.Column(db.String(64), nullable=False, index=True)
    endpoint = db.Column(db.String(32), nullable=False)
    username = db.Column(db.String(255), nullable=False, default="")
    client_ip = db.Column(db.String(64), nullable=False, default="")
    cohort = db.Column(db.String(64), nullable=False, default="")
    asn = db.Column(db.String(16), nullable=False, default="")
    outcome = db.Column(db.String(32), nullable=False, index=True)
    score = db.Column(db.Float, nullable=False, default=0.0)
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)


# Outcome vocabulary, shared by the app, the scoreboard and the checkpoint.
OUTCOME_SUCCESS = "success"          # session granted at the login endpoint
OUTCOME_INVALID = "invalid"          # wrong credentials
OUTCOME_THROTTLED = "throttled"      # L1 rate limit / lockout
OUTCOME_CHALLENGE = "challenge"      # L2 cohort flagged -> interactive challenge
OUTCOME_STEPUP = "step_up"           # correct password, second factor required
OUTCOME_STEPUP_PASS = "step_up_pass" # second factor completed -> session
OUTCOME_LOCKED = "locked"            # account locked
OUTCOME_ACCOUNT_READ = "account_read"       # /api/account served profile data
OUTCOME_SENSITIVE = "sensitive_action"      # a sensitive change was accepted
OUTCOME_REAUTH = "reauth_required"          # sensitive change needs re-auth

# A bot "takes over" an account when it obtains a session through the front door.
ATO_OUTCOMES = {OUTCOME_SUCCESS, OUTCOME_STEPUP_PASS}


def log_event(**kwargs) -> None:
    db.session.add(LoginEvent(ts=time.time(), **kwargs))
    db.session.commit()
