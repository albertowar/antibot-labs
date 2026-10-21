"""
W4 Ch11 Capstone — Shared helpers for the lab tools (checkpoint, simulator, scoreboard)

    BASE_URL      the demo store (DEMO_URL, default http://127.0.0.1:8409)
    authority()   host:port as it appears in the HTTP Host header (what signatures cover)
    admin()       call an /admin/ endpoint with the key derived from instance/lab_secret
    ensure_local  refuse anything that isn't this machine
"""

import hashlib
import os
import sys
from urllib.parse import urlparse

import requests

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:8409")
ensure_local = require_local


def authority(url=BASE_URL):
    return urlparse(url).netloc


def admin_key():
    path = os.path.join(INSTANCE, "lab_secret")
    if not os.path.exists(path):
        sys.exit("No instance/lab_secret yet. Start the demo site once: python demo_site/app.py")
    with open(path) as f:
        secret = f.read().strip()
    return hashlib.sha256(f"admin:{secret}".encode()).hexdigest()[:32]


def admin(method, path, **kwargs):
    ensure_local()
    headers = kwargs.pop("headers", {})
    headers["X-Lab-Admin"] = admin_key()
    r = requests.request(method, f"{BASE_URL}{path}", headers=headers, timeout=60, **kwargs)
    r.raise_for_status()
    return r.json()


def server_status():
    ensure_local()
    return requests.get(f"{BASE_URL}/admin/status", timeout=5).json()


def decisions(since_id=0, action=None):
    params = {"since_id": since_id}
    if action:
        params["action"] = action
    return admin("GET", "/admin/decisions", params=params)
