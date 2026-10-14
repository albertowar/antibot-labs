"""
Configuration: every knob the store reads from the environment, in one place.

Defaults are the zero-Docker path (SQLite + an in-process Redis). The compose
path sets DATABASE_URL and REDIS_URL. Nothing here is secret: this is a lab.
"""

import os
from dataclasses import dataclass

STORE_NAME = "Kestrel Outfitters"
STORE_HOST = "kestrel.test"
STORE_TAGLINE = "Trail-tested gear. Limited drops. No bots."

LAB_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return int(default)


@dataclass(frozen=True)
class Config:
    port: int
    database_url: str
    redis_url: str
    defense_level: int
    lab_seed: int
    lab_headers: bool
    lab_shadow: bool
    lab_shadow_checks: tuple
    lab_reload: bool
    drop_stock: int
    hash_iters: int
    world_file: str
    decision_log: str
    secret: str

    @classmethod
    def from_env(cls):
        instance = os.path.join(LAB_ROOT, "instance")
        os.makedirs(instance, exist_ok=True)
        return cls(
            port=_env_int("PORT", 5000),
            database_url=os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(instance, 'shop.db')}"),
            redis_url=os.environ.get("REDIS_URL", "memory://"),
            defense_level=_env_int("DEFENSE_LEVEL", 0),
            lab_seed=_env_int("LAB_SEED", 1337),
            lab_headers=os.environ.get("LAB_HEADERS", "1") != "0",
            lab_shadow=os.environ.get("LAB_SHADOW", "0") == "1",
            lab_shadow_checks=tuple(x for x in os.environ.get("LAB_SHADOW_CHECKS", "").split(",") if x),
            lab_reload=os.environ.get("LAB_RELOAD", "1") != "0",
            drop_stock=_env_int("DROP_STOCK", 50),
            hash_iters=_env_int("LAB_HASH_ITERS", 5000),
            world_file=os.environ.get("WORLD_FILE", os.path.join(LAB_ROOT, "data", "world.json")),
            decision_log=os.environ.get("DECISION_LOG", os.path.join(instance, "decisions.jsonl")),
            secret=os.environ.get("SECRET_KEY", "kestrel-lab-secret-not-for-production"),
        )
