/* Chapter 8: the login page's collector and challenge handling.
   A few lines of what W2 Ch2-4 built properly: a fingerprint and a short behaviour trace go to
   POST /api/telemetry (kind "risk"), then the sign-in goes to POST /api/login and any challenge
   that comes back is completed here. Without this script the form still posts to POST /login and
   the layers score "no telemetry". */
(function () {
  "use strict";
  var form = document.getElementById("login-form");
  if (!form || !window.fetch) return;
  var out = document.getElementById("risk-out");
  var t0 = performance.now(), mouse = [], keys = [], down = {}, pointerType = "mouse";
  var now = function () { return Math.round(performance.now() - t0); };

  addEventListener("pointermove", function (e) { if (mouse.length < 300) mouse.push([now(), e.clientX, e.clientY]); });
  addEventListener("pointerdown", function (e) { pointerType = e.pointerType; });
  addEventListener("keydown", function (e) { down[e.code] = now(); });
  addEventListener("keyup", function (e) { if (e.code in down) { keys.push([down[e.code], now()]); delete down[e.code]; } });

  function canvasHash() {
    var c = document.createElement("canvas"), x = c.getContext("2d");
    x.font = "16px Arial"; x.fillStyle = "#f60"; x.fillRect(10, 10, 100, 30);
    x.fillStyle = "#069"; x.fillText("antibot w2ch8", 2, 15);
    return c.toDataURL().slice(-48);
  }
  function renderer() {
    try {
      var g = document.createElement("canvas").getContext("webgl");
      var d = g.getExtension("WEBGL_debug_renderer_info");
      return g.getParameter(d ? d.UNMASKED_RENDERER_WEBGL : g.RENDERER);
    } catch (e) { return ""; }
  }
  function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }
  function sendTelemetry() {
    var fp = { platform: navigator.platform, webgl_renderer: renderer(), canvas: canvasHash(), canvas2: canvasHash(),
      screen: screen.width + "x" + screen.height, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      languages: navigator.languages, webdriver: navigator.webdriver, cdp: false, hardware_concurrency: navigator.hardwareConcurrency };
    return post("/api/telemetry", { kind: "risk", fp: fp, behavior: { mouse: mouse, keys: keys, pointer_type: pointerType } });
  }

  function zeroBits(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { n += 8; continue; }
      return n + Math.clz32(bytes[i]) - 24;
    }
    return n;
  }
  async function solve(p) {
    var enc = new TextEncoder();
    for (var n = 0; ; n++) {
      var d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(p.prefix + ":" + n)));
      if (zeroBits(d) >= p.bits) return String(n);
    }
  }
  function say(msg) { if (out) out.textContent = msg; }

  async function complete(challenge, payload) {
    if (challenge === "pow") {
      say("Checking your browser...");
      var t = performance.now(), nonce = await solve(payload);
      say("Solved in " + Math.round(performance.now() - t) + " ms.");
      return post("/api/challenge/verify", { type: "pow", answer: { nonce: nonce } });
    }
    var code = prompt("We emailed you a sign-in code (in the lab, read it at /lab/mailbox/<your email>):");
    return post("/api/challenge/verify", { type: "step_up", answer: { code: code || "" } });
  }

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var fd = new FormData(form);
    var body = { email: fd.get("email"), password: fd.get("password"), website: fd.get("website") || "" };
    try {
      await sendTelemetry();
      for (var round = 0; round < 3; round++) {
        var r = await post("/api/login", body), j = await r.json();
        if (r.ok) { location.href = fd.get("next") || "/account"; return; }
        var err = j.error || {};
        if (r.status === 403 && err.code === "challenge_required") {
          var v = await complete(err.challenge, err.payload);
          if (!v.ok) { say("That did not work: " + ((await v.json()).error || {}).message); return; }
          continue;                                   // the same login again, now with a clearance
        }
        say(r.status + " " + (err.message || "Could not sign in.") + (err.reasons ? "\n" + JSON.stringify(err, null, 1) : ""));
        return;
      }
    } catch (e) { say("Something went wrong: " + e); }
  });
})();
