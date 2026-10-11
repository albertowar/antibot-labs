/*
 * Chapter 9 — In-page collector (Sections 9.2–9.4)
 *
 * One script, two jobs:
 *   1. Fingerprint: the W2 Ch1 automation flags, and the W2 Ch4 coherence
 *      inputs (UA vs. UA-CH vs. platform, WebGL renderer, window geometry,
 *      a Web Worker's view of navigator).
 *   2. Behavior: pointer, click, key, touch and scroll events (W2 Ch3).
 *
 * Privacy: we record WHEN keys are pressed and whether a key was Tab or
 * Enter, never which character was typed. Collect the minimum the model
 * needs, and say so in your privacy notice.
 *
 * Everything here runs in the attacker's browser, so all of it can be read,
 * replayed or forged (W2 Ch2). The server treats it as evidence, never as
 * proof, and checks it against what it measures itself: TLS, timing, flow.
 */
(function () {
  "use strict";
  const t0 = performance.now();
  const MAX_MOVES = 400;
  const events = { moves: [], clicks: [], keys: [], touches: [], scrolls: 0, untrusted: 0 };
  const now = () => Math.round(performance.now() - t0);
  let lastMove = -1e9;

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
    const id = (e.target && (e.target.id || e.target.tagName)) || "";
    // detail === 0 means the click came from the keyboard (Enter/Space), not a pointer.
    events.clicks.push([now(), Math.round(e.clientX), Math.round(e.clientY), e.detail, id]);
  }, true);

  addEventListener("keydown", (e) => {
    trusted(e);
    const kind = e.key === "Tab" ? "Tab" : e.key === "Enter" ? "Enter" : "key";
    events.keys.push([now(), kind]);
  }, true);

  addEventListener("touchstart", (e) => {
    trusted(e);
    const t = e.touches[0];
    events.touches.push([now(), t ? Math.round(t.clientX) : 0, t ? Math.round(t.clientY) : 0]);
  }, { capture: true, passive: true });

  addEventListener("scroll", () => { events.scrolls++; }, { passive: true });

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
      c.width = 220; c.height = 40;
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px Arial";
      ctx.fillStyle = "#f60"; ctx.fillRect(10, 5, 100, 25);
      ctx.fillStyle = "#069"; ctx.fillText("Antibot lab \u{1F45F} 9", 4, 12);
      const data = c.toDataURL();
      let h = 0x811c9dc5;  // FNV-1a
      for (let i = 0; i < data.length; i++) { h ^= data.charCodeAt(i); h = Math.imul(h, 0x01000193); }
      return (h >>> 0).toString(16);
    } catch (err) {
      return null;
    }
  }

  // A dedicated Worker has its own navigator. Stealth tools that patch
  // navigator with JavaScript in the page often forget the worker, so the
  // two views disagree. Native (C++) spoofing, as in Camoufox, keeps them equal.
  function workerProbe() {
    return new Promise((resolve) => {
      try {
        const src = "postMessage({ua: navigator.userAgent, platform: navigator.platform," +
                    " hc: navigator.hardwareConcurrency, languages: navigator.languages})";
        const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
        const w = new Worker(url);
        const timer = setTimeout(() => { w.terminate(); resolve(null); }, 800);
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
