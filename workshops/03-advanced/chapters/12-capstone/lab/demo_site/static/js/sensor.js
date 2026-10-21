/*
 * W2 Ch1: the bot-detection sensor (Sections 1.2 to 1.4).
 *
 * Runs in the visitor's page, collects RAW facts about the JavaScript
 * environment and posts them to the store's telemetry sink
 * (POST /api/telemetry {"kind": "sensor", nonce, signals}) with the one-time
 * nonce the server put in the page (demo_site/ext/sensor.py). The sensor does not decide anything: all scoring
 * happens server-side (defenses/*.py), so the rules can change without
 * shipping new JavaScript and the attacker cannot read the thresholds.
 *
 * What it collects, by round:
 *   Round 1  navigator.webdriver, automation globals left by drivers
 *   Round 2  userAgentData vs. the HTTP hints, window/screen geometry,
 *            permission state, plugins, window.chrome, WebGL renderer
 *   Round 3  native-code integrity of the getters we read, own properties
 *            on navigator, the same values re-read from a Worker and an iframe
 *   Round 4  how the "Add to cart" click happened (isTrusted, pointer
 *            movement before it, distance from the button centre)
 *
 * Trade-off: everything here is a CLAIM made by the client. A bot that skips
 * the browser can POST whatever it likes (Round 5). Integrity of this payload
 * (obfuscation, signing, challenge binding) is Chapter 4.
 *
 * Plain ES2020 with no build step, so it runs as-is in Chrome, Edge, Firefox
 * and Safari. Every probe is wrapped: a sensor that throws on a real browser
 * is a false positive generator.
 */
(function () {
  "use strict";

  // Getters whose native-code integrity we check in Round 3.
  // [label, object holding the accessor, property]
  const GETTERS = [
    ["Navigator.webdriver", () => Navigator.prototype, "webdriver"],
    ["Navigator.userAgent", () => Navigator.prototype, "userAgent"],
    ["Navigator.platform", () => Navigator.prototype, "platform"],
    ["Navigator.languages", () => Navigator.prototype, "languages"],
    ["Navigator.plugins", () => Navigator.prototype, "plugins"],
    ["Navigator.hardwareConcurrency", () => Navigator.prototype, "hardwareConcurrency"],
    ["Navigator.userAgentData", () => Navigator.prototype, "userAgentData"],
    ["Screen.width", () => Screen.prototype, "width"],
    ["Screen.height", () => Screen.prototype, "height"],
    ["Screen.availHeight", () => Screen.prototype, "availHeight"],
    ["window.outerWidth", () => window, "outerWidth"],
    ["window.outerHeight", () => window, "outerHeight"],
    ["Notification.permission", () => window.Notification, "permission"],
  ];
  // Plain methods we also check
  const METHODS = [
    ["Permissions.query", () => window.Permissions && Permissions.prototype.query, "query"],
    ["WebGLRenderingContext.getParameter",
      () => window.WebGLRenderingContext && WebGLRenderingContext.prototype.getParameter, "getParameter"],
    ["Function.toString", () => Function.prototype.toString, "toString"],
  ];

  // Globals and document keys that automation drivers have been known to leave
  const SUSPICIOUS_KEY = /^(cdc_|\$cdc_|\$wdc_|__webdriver|__selenium|__driver|__fxdriver|_Selenium|callPhantom|_phantom|__nightmare|domAutomation|__playwright|__pw|__puppeteer)/;

  function safe(fn, fallback) {
    try { return fn(); } catch (e) { return fallback; }
  }

  function describeFunction(fn) {
    // Raw source text (truncated) plus whether it has a .prototype:
    // native getters and methods never do, plain `function () {}` replacements do.
    if (typeof fn !== "function") return null;
    return {
      src: safe(() => Function.prototype.toString.call(fn).slice(0, 120), "<threw>"),
      proto: Object.prototype.hasOwnProperty.call(fn, "prototype"),
    };
  }

  function nativeReport() {
    const out = {};
    for (const [label, holder, prop] of GETTERS) {
      const target = safe(holder, null);
      if (!target) continue;
      const desc = safe(() => Object.getOwnPropertyDescriptor(target, prop), null);
      if (desc && desc.get) out[label] = describeFunction(desc.get);
    }
    for (const [label, getFn] of METHODS) {
      const fn = safe(getFn, null);
      if (fn) out[label] = describeFunction(fn);
    }
    return out;
  }

  function webglInfo() {
    return safe(() => {
      const gl = document.createElement("canvas").getContext("webgl");
      if (!gl) return null;
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
      };
    }, null);
  }

  function workerReport() {
    // The same navigator values, read in a different JavaScript realm.
    // Init-script stealth patches usually only reach the page's main world.
    const code = `postMessage({
      ua: navigator.userAgent, platform: navigator.platform,
      languages: navigator.languages, hardware_concurrency: navigator.hardwareConcurrency,
      brands: navigator.userAgentData ? navigator.userAgentData.brands.map(b => b.brand) : null,
      webdriver: navigator.webdriver
    })`;
    return new Promise((resolve) => {
      let worker;
      const done = (value) => { resolve(value); if (worker) worker.terminate(); };
      try {
        worker = new Worker(URL.createObjectURL(new Blob([code], { type: "text/javascript" })));
        worker.onmessage = (e) => done(e.data);
        worker.onerror = () => done({ error: "worker error" });
      } catch (e) {
        done({ error: String(e && e.name) });
      }
      setTimeout(() => done({ error: "timeout" }), 1500);
    });
  }

  function iframeReport() {
    return safe(() => {
      const frame = document.createElement("iframe");
      frame.style.display = "none";
      document.body.appendChild(frame);
      const nav = frame.contentWindow.navigator;
      const report = { ua: nav.userAgent, platform: nav.platform, webdriver: nav.webdriver };
      frame.remove();
      return report;
    }, { error: "iframe" });
  }

  async function collect() {
    const started = performance.now();
    const nav = navigator;
    const signals = {
      // Round 1: automation artifacts
      webdriver: safe(() => nav.webdriver, null),
      suspicious_keys: safe(() => Object.getOwnPropertyNames(window)
        .concat(Object.keys(document)).filter((k) => SUSPICIOUS_KEY.test(k)).slice(0, 20), []),

      // Round 2: consistency
      ua: nav.userAgent,
      platform: nav.platform,
      languages: safe(() => Array.from(nav.languages), []),
      uad: safe(() => nav.userAgentData ? {
        brands: nav.userAgentData.brands.map((b) => b.brand + "/" + b.version),
        mobile: nav.userAgentData.mobile,
        platform: nav.userAgentData.platform,
      } : null, null),
      geometry: {
        outer_w: window.outerWidth, outer_h: window.outerHeight,
        inner_w: window.innerWidth, inner_h: window.innerHeight,
        screen_w: screen.width, screen_h: screen.height,
        avail_w: screen.availWidth, avail_h: screen.availHeight,
        dpr: window.devicePixelRatio,
      },
      notification_permission: safe(() => window.Notification ? Notification.permission : null, null),
      permission_query: null,
      plugins: safe(() => nav.plugins.length, null),
      has_chrome_object: typeof window.chrome === "object" && window.chrome !== null,
      webgl: webglInfo(),
      hardware_concurrency: nav.hardwareConcurrency,
      max_touch_points: nav.maxTouchPoints,

      // Round 3: lies
      native: nativeReport(),
      navigator_own_props: safe(() => Object.getOwnPropertyNames(nav), []),
      iframe: iframeReport(),
      worker: null,
    };

    signals.permission_query = await safe(
      () => nav.permissions.query({ name: "notifications" }).then((s) => s.state, () => "error"),
      Promise.resolve(null));
    signals.worker = await workerReport();
    signals.collect_ms = Math.round((performance.now() - started) * 10) / 10;
    return signals;
  }

  // ---- Round 4: how did the click happen? --------------------------------
  let pointerMoves = 0;
  document.addEventListener("pointermove", () => { pointerMoves += 1; }, { passive: true });

  function describeClick(event) {
    const rect = event.currentTarget.getBoundingClientRect();
    return {
      is_trusted: event.isTrusted,
      pointer_type: event.pointerType || "",   // "" for keyboard activation in Chromium
      detail: event.detail,                     // 0 = activated by keyboard / assistive tech
      offset_x: Math.round((event.clientX - (rect.left + rect.width / 2)) * 100) / 100,
      offset_y: Math.round((event.clientY - (rect.top + rect.height / 2)) * 100) / 100,
      moves_before: pointerMoves,
    };
  }

  async function send(nonce) {
    const signals = await collect();
    const response = await fetch("/api/telemetry", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "sensor", nonce, signals }),
    });
    return { ok: response.ok, signals };
  }

  window.ShopSensor = { collect, send, describeClick };
})();
