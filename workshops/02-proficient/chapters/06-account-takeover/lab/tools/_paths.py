"""Shared paths and base URL for the lab tools."""

import os

LAB = os.path.join(os.path.dirname(__file__), "..")
DATA = os.path.join(LAB, "data")
ATTACKS = os.path.join(LAB, "attacks")
BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
