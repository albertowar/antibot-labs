"""
Kestrel Outfitters: the demo store the Antibot Workshop Series defends.

    python demo_site/app.py                 # SQLite + in-process Redis, port 5000
    PORT=8099 DEFENSE_LEVEL=2 python demo_site/app.py
    docker compose up -d --wait && REDIS_URL=redis://127.0.0.1:6379/0 \
      DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py

Request path:  lab_edge (who is this, really?) -> gate.before_request (Ctx,
enrichers, ladder, policy) -> route -> gate.after_request (X-Lab-* headers,
decision log). Chapters add checks under defenses/ and features under
demo_site/ext/; see workshops/STORE_CONTRACT.md.
"""

import os
import sys

LAB_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if LAB_ROOT not in sys.path:
    sys.path.insert(0, LAB_ROOT)

from flask import Flask, render_template  # noqa: E402
from jinja2 import ChoiceLoader, FileSystemLoader  # noqa: E402
from sqlalchemy import event  # noqa: E402

from defenses import store  # noqa: E402
from defenses.decision_log import DecisionLog  # noqa: E402
from demo_site import ext, gate, hooks  # noqa: E402
from demo_site.config import STORE_NAME, Config  # noqa: E402
from demo_site.lab_edge import LabEdge, World  # noqa: E402
from demo_site.models import Decision, Product, db  # noqa: E402
from demo_site.routes import api, lab, pages, seo  # noqa: E402
from demo_site.seed import seed_all  # noqa: E402


def _sqlite_pragmas(dbapi_conn, _record):
    if "sqlite3" in type(dbapi_conn).__module__:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()


def create_app(config=None, seed=True):
    cfg = config or Config.from_env()
    here = os.path.dirname(os.path.abspath(__file__))
    app = Flask("demo_site", template_folder=os.path.join(here, "templates"), static_folder=os.path.join(here, "static"))
    app.config.update(SECRET_KEY=cfg.secret, SQLALCHEMY_DATABASE_URI=cfg.database_url,
                      SQLALCHEMY_TRACK_MODIFICATIONS=False, SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
                      LAB=cfg, STORE_NAME=STORE_NAME)
    app.jinja_loader = ChoiceLoader([FileSystemLoader(os.path.join(here, "ext", "templates")), app.jinja_loader])
    app.jinja_env.globals.update(slot=hooks.render_slot, store_name=STORE_NAME)

    db.init_app(app)
    with app.app_context():
        event.listen(db.engine, "connect", _sqlite_pragmas)
        db.create_all()
        if seed:
            seed_all(cfg.lab_seed, cfg.drop_stock, cfg.hash_iters)

    app.extensions["lab_redis"] = store.get_redis(cfg.redis_url)
    app.extensions["lab_world"] = World(cfg.world_file)
    app.extensions["decision_log"] = DecisionLog(app, db, Decision, cfg.decision_log)
    app.wsgi_app = LabEdge(app.wsgi_app, app.extensions["lab_world"])

    gate.install(app)
    for bp in (pages.bp, api.bp, seo.bp, lab.bp):
        app.register_blueprint(bp)
    ext.load_all(app)

    @app.errorhandler(404)
    def _404(_e):
        return render_template("error.html", code=404, message="We looked everywhere. That page is not on the map."), 404

    @app.errorhandler(500)
    def _500(_e):
        return render_template("error.html", code=500, message="Something went wrong on our side."), 500

    return app


if __name__ == "__main__":
    application = create_app()
    cfg = application.config["LAB"]
    print(f"{STORE_NAME} on http://127.0.0.1:{cfg.port}  level={cfg.defense_level}  "
          f"db={cfg.database_url.split('://')[0]}  redis={cfg.redis_url.split('://')[0]}  "
          f"ext={application.extensions['lab_ext']}")
    application.run(host="127.0.0.1", port=cfg.port, threaded=True, debug=False, use_reloader=False)
