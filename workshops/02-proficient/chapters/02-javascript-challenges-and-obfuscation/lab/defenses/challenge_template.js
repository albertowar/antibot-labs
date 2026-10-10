/*
 * Chapter 2 — Challenge script template (Sections 2.2, 2.4, 2.5)
 *
 * The server renders this template into:
 *   - Round 2: one fixed, readable script        (/challenge/l2.js)
 *   - Round 3+: a pool of variants, each with its own random op chain and probe
 *     size, then obfuscated with javascript-obfuscator (tools/build_variants.py)
 *
 * The loader on the challenge page has already fetched a signed challenge from
 * /challenge/new and left it in window.__ch = { token, nonce, env, script }.
 *
 * What this script proves to the server, by level:
 *   L2/L3: "something executed f(nonce)"         (f is fixed at L2, per-variant at L3)
 *   L4:    "...and it had a real layout engine and native DOM functions"
 *
 * Design rule: environment signals are folded INTO the answer. The script never
 * reports "isBot: false". A booleans-in-JSON design invites the attacker to
 * send the boolean they like; a hash that only comes out right when the
 * environment is right has to be computed, not claimed.
 *
 * Placeholders filled in by defenses/variants.py: __OPS__, __PROBE_W__,
 * __PROBE_P__, __PROBE_B__.
 */
(function () {
  var ch = window.__ch;
  var t0 = performance.now();

  // One step of the op chain. Every op is 32-bit unsigned arithmetic, so the
  // Python interpreter in defenses/variants.py gets bit-identical results.
  function step(h, c) {
    h = (h ^ c) >>> 0;
    __OPS__
    return h;
  }

  function isNative(fn) {
    // Real browsers implement DOM methods in C++: their source is "[native code]".
    // jsdom and happy-dom implement them in JavaScript, so their source shows.
    return typeof fn === "function" &&
      Function.prototype.toString.call(fn).indexOf("[native code]") !== -1;
  }

  function layoutProbe() {
    // A fixed-size box in CSS px (never em: users with a minimum-font-size
    // setting would get a different width, and we would block them).
    // visibility:hidden keeps it laid out; display:none would give 0 everywhere.
    var el = document.createElement("div");
    el.style.cssText = "position:absolute;left:-10000px;top:0;visibility:hidden;" +
      "box-sizing:content-box;width:__PROBE_W__px;padding:0 __PROBE_P__px;" +
      "border:__PROBE_B__px solid transparent";
    document.body.appendChild(el);
    var w = el.offsetWidth;          // 0 in an engine without layout
    document.body.removeChild(el);
    return w;
  }

  var h = 0x811c9dc5;
  for (var i = 0; i < ch.nonce.length; i++) {
    h = step(h, ch.nonce.charCodeAt(i));
  }

  if (ch.env) {
    h = step(h, layoutProbe());
    h = step(h, isNative(Element.prototype.getBoundingClientRect) &&
                isNative(Function.prototype.toString) ? 0x5bd1e995 : 0x0bad0bad);
    // Stack format: V8 frames look like "    at fn (url:1:2)"; SpiderMonkey and
    // JavaScriptCore use "fn@url:1:2". The server checks it matches the UA.
    var stack = String(new Error("probe").stack || "");
    h = step(h, /\n\s+at /.test(stack) ? 1 : 2);
  }

  var answer = ("0000000" + h.toString(16)).slice(-8);
  var solveMs = performance.now() - t0;

  fetch("/challenge/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: ch.token, answer: answer, solve_ms: solveMs })
  }).then(function (r) {
    window.__chDone = r.status;
    if (r.ok) {
      location.reload();
    } else {
      document.getElementById("challenge-status").textContent =
        "Verification failed (" + r.status + "). Reload to try again.";
    }
  });
})();
