/*
 * Chapter 2 — Round 3 Attack (Node side): run the challenge in jsdom
 *
 * "Don't read it, run it." Obfuscation and polymorphism make the challenge
 * expensive to READ. They do nothing against an attacker who EXECUTES it.
 * jsdom gives us a DOM, a cookie jar and script loading in plain Node.js, at
 * a fraction of a browser's memory and start-up time.
 *
 * What the attacker still has to build: shims for whatever the emulator
 * lacks. jsdom has no fetch(), so we add one that shares jsdom's cookie jar.
 * Every shim is a place where the emulator can differ from a browser, and
 * Round 4's defense looks for exactly those places.
 *
 * ⚠️ Attacker-side hazard: this runs the target's JavaScript with
 * runScripts: "dangerously", in your Node process. jsdom (like node:vm) is
 * NOT a security boundary. Hostile challenge code can reach Node APIs and your
 * filesystem. That's fine against your own lab site and reckless anywhere else.
 *
 * Usage (called by round3_jsdom_solver.py):
 *   node attacks/js/jsdom_solve.mjs <base_url> <user_agent>
 * Prints JSON: {"ok", "status", "reason", "cookies": {...}, "ms"}
 */
import jsdom from "jsdom";

const { JSDOM, CookieJar, VirtualConsole } = jsdom;   // jsdom is CommonJS

const [base, userAgent] = process.argv.slice(2);
const host = new URL(base).hostname;
if (!["localhost", "127.0.0.1", "::1"].includes(host)) {
  console.error(`Refusing to run against ${host}: lab attacks only target localhost.`);
  process.exit(2);
}

const t0 = performance.now();
const jar = new CookieJar();

async function jarFetch(url, init = {}) {
  const target = new URL(url, base).href;
  const headers = { ...(init.headers || {}), "User-Agent": userAgent,
                    Cookie: jar.getCookieStringSync(target) };
  const res = await fetch(target, { ...init, headers });
  for (const c of res.headers.getSetCookie()) jar.setCookieSync(c, target);
  return res;
}

// 1. Load the challenge page ourselves (it comes back as a 403).
const page = await jarFetch(`${base}/`);
const html = await page.text();

// 2. Hand it to jsdom with scripts on, our cookie jar and a fetch() shim.
const virtualConsole = new VirtualConsole();   // swallow "navigation not implemented"
let verifyBody = null;
const dom = new JSDOM(html, {
  url: `${base}/`,
  runScripts: "dangerously",
  resources: { userAgent },                      // also loads <script src>
  cookieJar: jar,
  pretendToBeVisual: true,
  virtualConsole,
  beforeParse(window) {
    window.fetch = (url, init) => jarFetch(url, init).then(async (r) => {
      const body = await r.text();
      if (String(url).includes("/challenge/verify")) verifyBody = body;
      return { ok: r.ok, status: r.status, json: async () => JSON.parse(body), text: async () => body };
    });
  },
});

// 3. Wait for the challenge script to report back (it sets window.__chDone).
const deadline = Date.now() + 10000;
while (dom.window.__chDone === undefined && Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 20));
}
const status = dom.window.__chDone ?? null;
const cookies = Object.fromEntries(
  jar.getCookiesSync(`${base}/`).map((c) => [c.key, c.value]));
dom.window.close();
let reason = status === null ? "challenge never completed" : null;
if (status !== 200 && verifyBody) reason = JSON.parse(verifyBody).reason;

console.log(JSON.stringify({
  ok: status === 200,
  status,
  reason,
  cookies,
  ms: Math.round(performance.now() - t0),
}));
