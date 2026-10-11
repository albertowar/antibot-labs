/*
 * W4 Ch4 — In-page collector
 *
 * The W2 Ch9 collector (fingerprint + pointer/key/touch events) plus four
 * things an agent-aware defender wants to know about *how* the page was used:
 *
 *   inputs          [t, field, charsInserted, keydownsSinceLastInput]
 *                   fill()/autofill set a value with no keystrokes; typing doesn't
 *   scroll_events   [t, programmatic]  a scroll with no wheel, key or touch just
 *                   before it came from scrollIntoView(), not from a person
 *   overlays        nodes appended to <body> that look like agent tooling:
 *                   fixed, pointer-events:none, enormous z-index, or named like a
 *                   highlight layer (early browser-use versions and several MCP
 *                   browser tools draw element boxes this way)
 *   clicks[].detail 0 means keyboard / assistive-technology activation
 *
 * Privacy: key events record WHEN and whether the key was Tab or Enter, never
 * which character. Input events record a character COUNT, never the text.
 *
 * Everything here runs in the client and can be forged (W2 Ch2). The server
 * treats it as evidence and checks it against what it measures itself: the
 * flow log, timing, and (Round 3) a signature it can verify.
 */
(function () {
  "use strict";
  const t0 = performance.now();
  const MAX_MOVES = 400;
  const events = { moves: [], clicks: [], keys: [], touches: [], inputs: [], scroll_events: [],
                   overlays: [], scrolls: 0, untrusted: 0 };
  const now = () => Math.round(performance.now() - t0);
  let lastMove = -1e9, lastHumanScrollIntent = -1e9, keydownsSinceInput = 0;
  const lastLen = new WeakMap();

  function trusted(e) { if (!e.isTrusted) events.untrusted++; }

  addEventListener("mousemove", (e) => {
    trusted(e);
    const t = now();
    if (t - lastMove < 15 || events.moves.length >= MAX_MOVES) return;
    lastMove = t;
    events.moves.push([t, Math.round(e.clientX), Math.round(e.clientY)]);
  }, { capture: true, passive: true });

  addEventListener("click", (e) => {
    trusted(e);
    const el = e.target && e.target.closest ? (e.target.closest("button, a, input") || e.target) : e.target;
    const id = (el && (el.id || el.tagName)) || "";
    // detail === 0: activated from the keyboard (Enter/Space) or by assistive technology.
    events.clicks.push([now(), Math.round(e.clientX), Math.round(e.clientY), e.detail, id]);
  }, true);

  addEventListener("keydown", (e) => {
    trusted(e);
    keydownsSinceInput++;
    if (["PageDown", "PageUp", "ArrowDown", "ArrowUp", " ", "End", "Home"].includes(e.key)) lastHumanScrollIntent = now();
    const kind = e.key === "Tab" ? "Tab" : e.key === "Enter" ? "Enter" : "key";
    events.keys.push([now(), kind]);
  }, true);

  addEventListener("input", (e) => {
    const el = e.target;
    if (!el || !("value" in el)) return;
    const prev = lastLen.get(el) || 0;
    const len = String(el.value || "").length;
    const inserted = Math.max(0, len - prev);
    lastLen.set(el, len);
    if (inserted > 0 && events.inputs.length < 50) {
      events.inputs.push([now(), el.name || el.id || el.tagName, inserted, keydownsSinceInput]);
    }
    keydownsSinceInput = 0;
  }, true);

  addEventListener("wheel", () => { lastHumanScrollIntent = now(); }, { capture: true, passive: true });
  addEventListener("touchmove", () => { lastHumanScrollIntent = now(); }, { capture: true, passive: true });

  addEventListener("touchstart", (e) => {
    trusted(e);
    const t = e.touches[0];
    events.touches.push([now(), t ? Math.round(t.clientX) : 0, t ? Math.round(t.clientY) : 0]);
  }, { capture: true, passive: true });

  addEventListener("scroll", () => {
    events.scrolls++;
    const t = now();
    if (events.scroll_events.length < 50) events.scroll_events.push([t, t - lastHumanScrollIntent > 150 ? 1 : 0]);
  }, { passive: true });

  // Agent tooling overlays: watch what gets appended to <body> after load.
  const OVERLAY_NAME = /highlight|overlay|agent|annotat|bounding/i;
  function looksLikeOverlay(el) {
    if (!(el instanceof Element) || el.id === "result") return false;
    let cs;
    try { cs = getComputedStyle(el); } catch (err) { return false; }
    const z = parseInt(cs.zIndex, 10) || 0;
    const fixed = cs.position === "fixed" || cs.position === "absolute";
    const passthrough = cs.pointerEvents === "none";
    const named = OVERLAY_NAME.test(el.id) || OVERLAY_NAME.test(el.className) ||
                  Array.from(el.attributes).some((a) => OVERLAY_NAME.test(a.name));
    return (fixed && passthrough && z >= 1000) || named;
  }
  if (window.MutationObserver) {
    new MutationObserver((muts) => {
      for (const m of muts) for (const n of m.addedNodes) {
        if (events.overlays.length < 10 && looksLikeOverlay(n)) {
          events.overlays.push({ id: n.id || "", cls: String(n.className || "").slice(0, 40),
                                 z: getComputedStyle(n).zIndex, t: now() });
        }
      }
    }).observe(document.body, { childList: true });
  }

  function webgl() {
    try {
      const gl = document.createElement("canvas").getContext("webgl");
      if (!gl) return { vendor: null, renderer: null };
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: gl.getParameter(ext ? ext.UNMASKED_VENDOR_WEBGL : gl.VENDOR),
        renderer: gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER),
      };
    } catch (err) {
      return { vendor: null, renderer: null };
    }
  }

  function canvasHash() {
    try {
      const c = document.createElement("canvas");
      c.width = 200; c.height = 40;
      const ctx = c.getContext("2d");
      ctx.font = "16px Arial";
      ctx.fillStyle = "#f60"; ctx.fillRect(10, 5, 60, 25);
      ctx.fillStyle = "#069"; ctx.fillText("Lab Store 🛒", 12, 24);
      const data = c.toDataURL();
      let h = 0;
      for (let i = 0; i < data.length; i++) h = (h * 31 + data.charCodeAt(i)) >>> 0;
      return h.toString(16);
    } catch (err) { return null; }
  }

  function workerProbe() {
    return new Promise((resolve) => {
      try {
        const src = "postMessage({ua:navigator.userAgent,platform:navigator.platform,hc:navigator.hardwareConcurrency,languages:Array.from(navigator.languages||[])})";
        const w = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
        const timer = setTimeout(() => resolve(null), 800);
        w.onmessage = (m) => { clearTimeout(timer); w.terminate(); resolve(m.data); };
        w.onerror = () => { clearTimeout(timer); resolve(null); };
      } catch (err) {
        resolve(null);
      }
    });
  }

  async function fingerprint() {
    const n = navigator;
    const automationGlobals = Object.keys(window).filter((k) =>
      /^\$?cdc_|^__(webdriver|selenium|fxdriver|driver)_|^__pwInitScripts$|^__playwright/.test(k));
    const fp = {
      webdriver: n.webdriver === true,
      automation_globals: automationGlobals,
      ua: n.userAgent,
      platform: n.platform,
      languages: Array.from(n.languages || []),
      hc: n.hardwareConcurrency || null,
      mem: n.deviceMemory || null,
      touch_points: n.maxTouchPoints || 0,
      plugins: n.plugins ? n.plugins.length : 0,
      screen: [screen.width, screen.height, screen.availWidth, screen.availHeight],
      win: [outerWidth, outerHeight, innerWidth, innerHeight],
      dpr: devicePixelRatio,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      webgl: webgl(),
      canvas: canvasHash(),
      uach: null,
      worker: null,
    };
    if (n.userAgentData) {
      try {
        const high = await n.userAgentData.getHighEntropyValues(["platformVersion"]);
        fp.uach = {
          brands: n.userAgentData.brands.map((b) => b.brand),
          platform: n.userAgentData.platform,
          mobile: n.userAgentData.mobile,
          platform_version: high.platformVersion,
        };
      } catch (err) { /* hints unavailable */ }
    }
    fp.worker = await workerProbe();
    return fp;
  }

  const fpPromise = fingerprint();

  window.labTelemetry = {
    events,
    fingerprint: () => fpPromise,
    // Send everything collected on this page; resolves to the server's reply.
    async flush() {
      const body = { page: location.pathname, fp: await fpPromise, events, t_ms: now() };
      const r = await fetch("/api/telemetry", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      return r.json();
    },
  };
})();
