"""
Contract test: does this store still honour workshops/STORE_CONTRACT.md?

Runs against a live store (DEMO_URL) and checks every canonical route, the
X-Lab-* headers, seed counts, the DOM contract (selectors attacks depend on),
the lab edge rules, and that no defense reads the ground-truth actor label.

    python tools/smoke.py            # against a running store
    python tools/verify.py --smoke   # starts one for you
"""

import os
import re
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from labclient import BASE_URL, LabClient, admin, csrf_of, world_pool  # noqa: E402

DOM = {
    "/products": [r'class="product-card" data-sku="', r'id="cart-count"'],
    "/product/p001": [r'id="add-to-cart"', r'name="sku"', r'name="csrf"', r'name="qty"'],
    "/drop/lab-hoodie-1": [r'id="drop-buy"[^>]*data-sku="lab-hoodie-1"', r'name="size"', r'name="email"'],
    "/login": [r'id="login-form"', r'name="email"', r'name="password"'],
    "/register": [r'id="register-form"'],
    "/gift-cards": [r'name="code"'],
}
GETS = ["/", "/products", "/catalog", "/products?category=shoes&sort=price_asc&page=2", "/search?q=runner", "/product/p001",
        "/drop/lab-runner-9", "/cart", "/login", "/register", "/gift-cards", "/robots.txt", "/sitemap.xml", "/feed.xml",
        "/health", "/img/p001.svg", "/static/css/store.css", "/api/products", "/api/products/p001", "/api/search?q=pack",
        "/api/reviews/p001", "/api/cart", "/whoami", "/lab/status", "/lab/config", "/lab/decisions?limit=5", "/lab/scoreboard"]

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)
        print("  FAIL", msg)


def check_world(client):
    """world.json, labclient and build_world agree; spread pools really spread; groups resolve."""
    import ipaddress
    import build_world
    from labclient import WORLD
    problems = build_world.validate(WORLD)
    check(not problems, f"world.json rules: {problems}")
    for k, v in build_world.build(WORLD).items():
        path = os.path.join(build_world.FEEDS, k)
        check(os.path.exists(path) and open(path).read() == v, f"data/feeds/{k} is stale: run python tools/build_world.py")
    for name, p in WORLD["pools"].items():
        check(world_pool(name) == build_world.hosts(p), f"world_pool({name}) disagrees with build_world.hosts")
        if "spread" in p:
            ips = world_pool(name)
            nets = {ipaddress.ip_network(f"{ip}/{p['spread']}", strict=False) for ip in ips}
            check(len(nets) == len(ips), f"{name}: spread pool hosts share a /{p['spread']}")
            r = client.get("/whoami", ip=ips[-1])
            check(r.status_code == 200 and r.json()["pool"] == name, f"edge: {name} host {ips[-1]} -> {r.status_code}")
    for g, members in WORLD.get("groups", {}).items():
        ips = world_pool(g)
        check(ips and len(set(ips)) == len(ips), f"group {g}: empty or duplicate addresses")


def check_bucket():
    """ctx.bucket's Lua script must run on the configured backend (plain fakeredis has no Lua)."""
    from defenses import store as dstore
    try:
        r = dstore.get_redis()
        takes = [dstore.token_bucket(r, "smoke", "smoke-bucket", limits={"smoke": (2, 0.001)}) for _ in range(3)]
        check(takes == [True, True, False], f"token_bucket: bucket of 2 gave {takes}, expected [True, True, False]")
    except Exception as e:
        check(False, f"token_bucket raised {type(e).__name__}: {e} (fakeredis needs the [lua] extra)")


def run():
    admin("POST", "/lab/reset")
    check_bucket()
    for path in GETS:
        r = requests.get(BASE_URL + path, timeout=30)
        check(r.status_code == 200, f"GET {path} -> {r.status_code}")
        if not path.startswith(("/lab", "/whoami", "/health", "/static", "/img")):
            check("X-Lab-Verdict" in r.headers and "X-Lab-Score" in r.headers and "Server-Timing" in r.headers, f"{path}: missing X-Lab-* headers")
    for path, pats in DOM.items():
        html = requests.get(BASE_URL + path, timeout=30).text
        for pat in pats:
            check(re.search(pat, html), f"DOM contract: {path} lacks {pat}")
    st = admin("GET", "/lab/status")
    check(st["products"] == 122, f"seed: {st['products']} products, expected 122")
    check(st["users"] == 301, f"seed: {st['users']} users, expected 301")
    api = requests.get(BASE_URL + "/api/products", timeout=30).json()
    check(set(api) >= {"items", "page", "pages", "total"} and api["total"] == 120, "api list shape / 120 visible products")
    p = requests.get(BASE_URL + "/api/products/p001", timeout=30).json()
    check("price_cents" in p and "stock" in p and p["image"] == "/img/p001.svg", "api product shape")
    err = requests.get(BASE_URL + "/api/products/nope", timeout=30)
    check(err.status_code == 404 and err.json()["error"]["code"] == "not_found", "api error shape")

    # Lab edge rules
    r = requests.get(BASE_URL + "/whoami", headers={"X-Lab-Client-IP": "8.8.8.8"}, timeout=30)
    check(r.status_code == 421, "edge: invented IP must be 421")
    c = LabClient("bot:smoke", ip=world_pool("cloud_vm")[0])
    r = c.get("/whoami", headers=[("X-Forwarded-For", "1.2.3.4"), ("X-Lab-Foo", "bar")])
    j = r.json()
    check(j["ip"] == world_pool("cloud_vm")[0] and j["asn"] == 64501, "edge: rented IP resolves to pool ASN")
    check(j["actor"] == "bot:smoke", "edge: actor passes to whoami")
    check(j["xff_claimed"] == f"1.2.3.4, {world_pool('cloud_vm')[0]}", f"edge: client XFF kept as a claimed chain: {j['xff_claimed']}")
    check(c.get("/whoami").json()["xff_claimed"] == world_pool("cloud_vm")[0], "edge: no client XFF -> claimed chain is the peer")
    check_world(c)
    check(c.get("/api/products").status_code == 200, "bot can list products at level 0")
    r = requests.get(BASE_URL + "/whoami", timeout=30).json()
    check(r["ip"] == "192.0.2.10", "edge: no header -> student_ip")

    # Shopper flow: browse, cart, checkout, login, review, gift card, telemetry
    shopper = LabClient("human:smoke:00", ip=world_pool("home_broadband")[5])
    html = shopper.get("/product/p002").text
    csrf = csrf_of(html)
    r = shopper.post("/cart/add", {"csrf": csrf, "sku": "p002", "size": "", "qty": "2", "next": "/cart"})
    check(r.status_code in (302, 303), f"cart add -> {r.status_code}")
    check(shopper.get("/api/cart").json()["count"] == 2, "cart count via api")
    r = shopper.post("/checkout", {"csrf": csrf, "email": "smoke@example.test", "name": "S", "address": "1", "city": "B", "postcode": "1",
                                   "card": "4242", "exp": "12/29", "cvc": "123"})
    check(r.status_code == 200 and 'data-testid="order-confirmed"' in r.text, f"checkout -> {r.status_code}")
    r = shopper.post("/api/login", json={"email": "user031@example.test", "password": __import__("demo_site.seed", fromlist=["x"]).password_for(31)})
    check(r.status_code == 200 and r.json()["ok"], f"api login -> {r.status_code} {r.text[:80]}")
    r = shopper.post("/api/login", json={"email": "user031@example.test", "password": "wrong"})
    check(r.status_code == 401, "api login wrong password -> 401")
    r = shopper.get("/api/account")
    check(r.status_code == 200 and r.json()["email"] == "user031@example.test", "api account")
    r = shopper.post("/api/reviews", json={"sku": "p003", "rating": 4, "title": "ok", "body": "fine"})
    check(r.status_code == 201, f"api review -> {r.status_code}")
    r = shopper.post("/api/telemetry", json={"kind": "smoke", "x": 1})
    check(r.status_code == 200 and r.json()["kind"] == "smoke", "telemetry sink")
    r = shopper.get("/api/gift-cards/balance?code=GC-NOPE-NOPE")
    check(r.status_code == 404, "gift card miss -> 404")
    r = shopper.post("/api/buy", json={"sku": "lab-hoodie-1", "size": "M", "email": "smoke@example.test"})
    check(r.status_code == 201 and r.json()["ok"], f"api drop buy -> {r.status_code} {r.text[:80]}")
    r = shopper.post("/api/buy", json={"sku": "lab-runner-9", "size": "9"})
    check(r.status_code == 201, f"api drop buy runner (logged in, limit 1) -> {r.status_code}")
    r = shopper.post("/api/buy", json={"sku": "lab-runner-9", "size": "9"})
    check(r.status_code == 409, f"api drop buy runner second time -> {r.status_code} (expected 409 limit)")
    r = shopper.get("/api/challenge?type=nope")
    check(r.status_code == 404, "unknown challenge -> 404")
    board = admin("GET", "/lab/scoreboard")
    check(board["summary"]["purchases"].get("human", 0) >= 3, f"scoreboard counts purchases: {board['summary']['purchases']}")
    kinds = {a["actor"] for a in board["actors"]}
    check("human:smoke" in kinds and "bot:smoke" in kinds, f"scoreboard groups actors: {kinds}")
    dec = admin("GET", "/lab/decisions?actor=human:smoke&limit=3")
    check(dec["total"] >= 5 and all(d["actor"].startswith("human:smoke") for d in dec["items"]), "decision log filter by actor")

    # Ground truth never reaches a defense
    for sub in ("defenses", os.path.join("demo_site", "ext")):
        for root, _, files in os.walk(os.path.join(LAB, sub)):
            for f in files:
                if f.endswith(".py"):
                    src = open(os.path.join(root, f)).read()
                    check('lab.actor"' not in src and 'X-Lab-Actor"' not in src and "HTTP_X_LAB_ACTOR" not in src,
                          f"{sub}/{f} reads the ground-truth actor label")
    print("\nsmoke:", "OK" if not fails else f"{len(fails)} failures")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(run())
