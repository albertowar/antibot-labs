"""
Chapter 9 — Shared helpers for the lab tools (checkpoint, simulator, training)

    BASE_URL      the demo store (DEMO_URL, default https://localhost:8443)
    admin()       call an /admin/ endpoint with the key from instance/lab_secret
    ensure_local  refuse anything that isn't this machine
"""

import hashlib
import os
import sys
import warnings
from urllib.parse import urlparse

import requests
import urllib3

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTANCE = os.path.join(LAB_DIR, "instance")
BASE_URL = os.environ.get("DEMO_URL", "https://localhost:8443").rstrip("/")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# The lab certificate is self-signed; verification is skipped for localhost only.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def ensure_local(url=BASE_URL):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to run against {host!r}: lab tools only target this machine.")
    return url


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
    r = requests.request(method, f"{BASE_URL}{path}", headers=headers, verify=False, timeout=30, **kwargs)
    r.raise_for_status()
    return r.json()


def server_status():
    ensure_local()
    return requests.get(f"{BASE_URL}/admin/status", verify=False, timeout=5).json()
