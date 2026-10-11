"""Chapter 7: is this machine ready? Versions, the data file and its digest."""

import hashlib
import gzip
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
DATA = os.path.join(LAB, "data", "account_activity.jsonl.gz")
KEY = os.path.join(LAB, "solutions", "answer_key.json")
WANT = {"numpy": "2.2.6", "pandas": "2.3.3", "sklearn": "1.7.2", "networkx": "3.4.2", "matplotlib": "3.10.6"}


def main():
    ok = True
    print(f"python {sys.version.split()[0]}  ({'ok' if sys.version_info >= (3, 10) else 'need 3.10+'})")
    for mod, want in WANT.items():
        try:
            m = __import__(mod)
            v = m.__version__
            print(f"{mod:<11s} {v:<8s} {'ok' if v == want else 'pinned ' + want}")
        except ImportError:
            print(f"{mod:<11s} MISSING   pip install -r requirements.txt")
            ok = False
    try:
        import jupyterlab  # noqa: F401
        print("jupyterlab  ok")
    except ImportError:
        print("jupyterlab  MISSING   (notebooks need it; the scripts do not)")
    if not os.path.exists(DATA):
        print(f"data        MISSING   run: python tools/make_log.py   (about a minute)")
        return 1
    size = os.path.getsize(DATA) / 1e6
    with open(KEY) as f:
        want = json.load(f)["sha256_uncompressed"]
    h = hashlib.sha256()
    n = 0
    with gzip.open(DATA, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += chunk.count(b"\n")
    match = h.hexdigest() == want
    print(f"data        {size:.0f} MB gz, {n} lines, digest {'matches the answer key' if match else 'DOES NOT MATCH the answer key: regenerate with the default seed'}")
    return 0 if ok and match else 1


if __name__ == "__main__":
    sys.exit(main())
