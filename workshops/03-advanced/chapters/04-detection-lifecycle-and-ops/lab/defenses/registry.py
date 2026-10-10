"""
Chapter 4 (W3): The model registry, in one JSON file

    ../models/manifest.json
      {"versions": {"v1": {"trained_on": [1,2,3], "labels": "weak", "t_suspicious": .., "t_bot": ..,
                           "metrics": {...}, "created": "...", "status": "retired|candidate|prod|shadow|canary"}},
       "roles": {"prod": "v1", "shadow": null, "canary": null}}

    ../models/model_v1.txt     the LightGBM booster

Roles, not versions, are what the pipeline reads: `prod` scores and acts,
`shadow` scores and only logs, `canary` scores and acts for canary_pct of
sessions. Changing a role is a file write that the app picks up on the next
request (defenses/model.py hot-reloads on mtime).

This is what MLflow's Model Registry gives you with a UI, lineage, access
control and an API, and what you should use once more than one person
promotes models. The lab keeps it to a file so you can read every field.
"""

import json
import os
import threading
import time

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MODELS_DIR = os.path.join(LAB, "models")
MANIFEST = os.path.join(MODELS_DIR, "manifest.json")
ROLES = ("prod", "shadow", "canary")
_lock = threading.Lock()


def _read():
    if not os.path.exists(MANIFEST):
        return {"versions": {}, "roles": {r: None for r in ROLES}}
    with open(MANIFEST) as f:
        return json.load(f)


def _write(data):
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(MANIFEST, "w") as f:
        json.dump(data, f, indent=2)


def load():
    with _lock:
        return _read()


def model_path(version):
    return os.path.join(MODELS_DIR, f"model_{version}.txt")


def next_version():
    versions = _read()["versions"]
    return f"v{len(versions) + 1}"


def register(version, meta):
    with _lock:
        data = _read()
        data["versions"][version] = {**meta, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                                     "status": "candidate"}
        _write(data)
    return version


def set_role(role, version):
    """Give `version` the role (or clear the role with version=None)."""
    assert role in ROLES
    with _lock:
        data = _read()
        if version is not None and version not in data["versions"]:
            raise SystemExit(f"Unknown model version {version}. Known: {', '.join(data['versions']) or 'none'}")
        previous = data["roles"].get(role)
        if previous and previous != version:
            holds = [r for r, v in data["roles"].items() if v == previous and r != role]
            data["versions"][previous]["status"] = holds[0] if holds else "retired"
        data["roles"][role] = version
        if version:
            data["versions"][version]["status"] = role
        _write(data)
    return previous


def get(role):
    data = _read()
    version = data["roles"].get(role)
    return (version, data["versions"].get(version)) if version else (None, None)


def describe():
    data = _read()
    lines = [f"{'version':<8} {'status':<10} {'trained on':<12} {'labels':<14} {'t_sus':>5} {'t_bot':>5}  metrics"]
    for v, meta in data["versions"].items():
        m = meta.get("metrics", {})
        lines.append(f"{v:<8} {meta['status']:<10} {'weeks ' + ','.join(map(str, meta['trained_on'])):<12} "
                     f"{meta['labels']:<14} {meta['t_suspicious']:>5.2f} {meta['t_bot']:>5.2f}  "
                     + ", ".join(f"{k} {val}" for k, val in m.items()))
    lines.append("roles: " + ", ".join(f"{r}={v or '-'}" for r, v in data["roles"].items()))
    return "\n".join(lines)
