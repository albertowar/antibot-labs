"""Shared paths and base URL for the lab tools."""

import os
import sys

LAB = os.path.join(os.path.dirname(__file__), "..")
DATA = os.path.join(LAB, "data")
ATTACKS = os.path.join(LAB, "attacks")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")

