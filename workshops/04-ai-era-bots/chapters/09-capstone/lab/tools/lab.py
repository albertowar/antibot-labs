"""
W4 Ch9 Capstone — Shared helpers for the lab tools (checkpoint, simulator, scoreboard)

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
BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:8409").rstrip("/")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def ensure_local(url=BASE_URL):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to run against {host!r}: lab tools only target this machine.")
    return url


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
