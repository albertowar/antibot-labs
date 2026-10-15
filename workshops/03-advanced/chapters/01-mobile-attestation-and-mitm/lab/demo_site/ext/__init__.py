"""
Chapter extensions. Every demo_site/ext/<name>.py with an init(app) function is
imported in name order and initialised after the core routes. A chapter adds a
feature here instead of editing starter files:

    # demo_site/ext/pow.py
    from demo_site import hooks
    def init(app):
        hooks.challenges.register("pow", issue, verify, render="pow/interstitial.html")
        hooks.slot("body_end", "pow/solver.html")

Chapter templates live in demo_site/ext/templates/<name>/ (searched before the
starter templates, so a chapter may override one) and chapter JS in
demo_site/static/js/<name>.js.
"""

import importlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_all(app):
    loaded = []
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        mod = importlib.import_module(f"demo_site.ext.{name[:-3]}")
        if hasattr(mod, "init"):
            mod.init(app)
            loaded.append(name[:-3])
    app.extensions["lab_ext"] = loaded
    return loaded
