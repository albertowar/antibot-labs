"""Hygiene routes crawlers and monitors expect: robots, sitemap, feed, health, images."""

from flask import Blueprint, Response, request, url_for

from .. import hooks
from ..images import svg
from ..models import Product

bp = Blueprint("seo", __name__)


@bp.route("/robots.txt")
def robots():
    lines = ["User-agent: *", "Allow: /", "Disallow: /cart", "Disallow: /checkout",
             "Disallow: /account", "Disallow: /lab/"]
    for provider in hooks.ROBOTS:          # chapter lines (hooks.robots), e.g. bait Disallow entries
        lines += [str(line) for line in provider()]
    body = "\n".join(lines) + f"\nSitemap: {request.url_root}sitemap.xml\n"
    return Response(body, mimetype="text/plain")


@bp.route("/sitemap.xml")
def sitemap():
    urls = [request.url_root.rstrip("/") + "/", request.url_root + "products"]
    urls += [request.url_root + p.to_dict()["url"].lstrip("/") for p in Product.query.filter_by(hidden=False).order_by(Product.id)]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + \
        "".join(f"  <url><loc>{u}</loc></url>\n" for u in urls) + "</urlset>\n"
    return Response(body, mimetype="application/xml")


@bp.route("/feed.xml")
def feed():
    items = Product.query.filter_by(hidden=False).order_by(Product.id.desc()).limit(20)
    body = '<?xml version="1.0"?><rss version="2.0"><channel><title>Kestrel Outfitters</title>' \
           f'<link>{request.url_root}</link><description>New arrivals and drops</description>'
    for p in items:
        body += f"<item><title>{p.name}</title><link>{request.url_root}{p.to_dict()['url'].lstrip('/')}</link>" \
                f"<description>{p.blurb}</description><guid>{p.sku}</guid></item>"
    return Response(body + "</channel></rss>", mimetype="application/rss+xml")


@bp.route("/health")
def health():
    return {"ok": True}


@bp.route("/img/<sku>.svg")
def image(sku):
    p = Product.query.filter_by(sku=sku).first()
    width = max(64, min(1024, request.args.get("w", 320, type=int)))
    body = svg(sku, p.category if p else "kitchen", p.name if p else sku, width)
    r = Response(body, mimetype="image/svg+xml")
    r.headers["Cache-Control"] = "public, max-age=3600"
    r.headers["ETag"] = f'"{sku}-{width}"'
    return r


@bp.route("/favicon.ico")
def favicon():
    return Response(status=204)
