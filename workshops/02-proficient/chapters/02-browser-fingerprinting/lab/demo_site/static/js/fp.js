// @ts-check
/**
 * Chapter 2 — Fingerprint Collector (Sections 4.2–4.6)
 *
 * Collects raw OBSERVATIONS and posts them to the store's telemetry sink,
 * POST /api/telemetry {"kind": "fp", ...}, with the session's nonce
 * (window.__fpNonce, written into the page by the ext). It makes no
 * judgements: every decision lives in the Python defenses on the server,
 * because this file runs on the attacker's machine and anything it decides
 * can be patched out. (Hiding and hardening the collector itself is
 * Workshop 2, Chapter 4.)
 *
 * Signal families:
 *   nav      navigator values (main thread)
 *   uad      navigator.userAgentData, low + high entropy
 *   screen   screen and window geometry
 *   intl     timezone and locale
 *   canvas   2D render hash, rendered twice, plus a known-pixel probe
 *   webgl    vendor/renderer strings, capability limits, extension list
 *   audio    OfflineAudioContext render (no autoplay prompt, no sound)
 *   fonts    installed-font probe via text measurement
 *   voices   speechSynthesis voice list
 *   worker   the same navigator values, read inside a Web Worker
 *   lies     shape of the native functions/getters a spoofer would patch
 *
 * Cost: ~20–150 ms of main-thread time on a laptop (reported as
 * `collect_ms`), one extra request, and a 3–6 KB JSON payload.
 *
 * Privacy: everything is hashed or reduced before it leaves the page,
 * except the values the server needs to compare (renderer, platform, ...).
 * Collect only what a defense uses, and say so in your privacy notice.
 */
(function () {
  "use strict";

  /** @param {string} text */
  async function sha256(text) {
    const data = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 16);
  }

  /** @template T @param {() => T} fn @param {T | null} [fallback] */
  function safe(fn, fallback = null) {
    try {
      return fn();
    } catch (e) {
      return fallback;
    }
  }

  // ── navigator ────────────────────────────────────────────────────────────
  function collectNavigator() {
    const n = /** @type {any} */ (navigator);
    return {
      userAgent: n.userAgent,
      platform: n.platform,
      language: n.language,
      languages: Array.from(n.languages || []),
      hardwareConcurrency: n.hardwareConcurrency ?? null,
      deviceMemory: n.deviceMemory ?? null,
      maxTouchPoints: n.maxTouchPoints ?? null,
      vendor: n.vendor,
      pdfViewerEnabled: n.pdfViewerEnabled ?? null,
    };
  }

  // ── User-Agent Client Hints, JS side (compare with Sec-CH-UA headers) ─────
  async function collectUserAgentData() {
    const uad = /** @type {any} */ (navigator).userAgentData;
    if (!uad) return null; // Firefox and Safari don't implement it
    const out = {
      brands: (uad.brands || []).map((/** @type {any} */ b) => `${b.brand}/${b.version}`),
      mobile: uad.mobile,
      platform: uad.platform,
      high: /** @type {any} */ (null),
    };
    try {
      out.high = await uad.getHighEntropyValues([
        "platformVersion", "architecture", "bitness", "model", "fullVersionList",
      ]);
      out.high.fullVersionList = (out.high.fullVersionList || [])
        .map((/** @type {any} */ b) => `${b.brand}/${b.version}`);
      delete out.high.brands;
      delete out.high.mobile;
      delete out.high.platform;
    } catch (e) {
      out.high = null;
    }
    return out;
  }

  // ── screen ───────────────────────────────────────────────────────────────
  function collectScreen() {
    return {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      devicePixelRatio: window.devicePixelRatio,
    };
  }

  function collectIntl() {
    const opts = Intl.DateTimeFormat().resolvedOptions();
    return {
      timeZone: opts.timeZone,
      locale: opts.locale,
      tzOffset: new Date().getTimezoneOffset(),
    };
  }

  // ── canvas ───────────────────────────────────────────────────────────────
  // The same drawing twice: a real browser returns identical pixels, a
  // per-call noise injector does not. The probe paints known solid colours
  // and reads them back: any change there is injected noise, not rendering.
  function drawScene() {
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    const ctx = /** @type {CanvasRenderingContext2D} */ (c.getContext("2d"));
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(100, 1, 80, 22);
    ctx.fillStyle = "#069";
    ctx.font = "16px Arial, sans-serif";
    ctx.fillText("Cwm fjordbank glyphs vext quiz \u{1F60A}", 2, 18);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.font = "18px Georgia, serif";
    ctx.fillText("Cwm fjordbank ≠ bot", 4, 45);
    ctx.globalCompositeOperation = "multiply";
    ctx.beginPath();
    ctx.arc(200, 35, 20, 0, Math.PI * 2);
    ctx.fillStyle = "rgb(255, 0, 255)";
    ctx.fill();
    return c.toDataURL();
  }

  function canvasProbe() {
    const c = document.createElement("canvas");
    c.width = 8;
    c.height = 8;
    const ctx = /** @type {CanvasRenderingContext2D} */ (c.getContext("2d"));
    ctx.fillStyle = "rgb(10, 20, 30)";
    ctx.fillRect(0, 0, 8, 8);
    const px = ctx.getImageData(0, 0, 8, 8).data;
    let changed = 0;
    for (let i = 0; i < px.length; i += 4) {
      if (px[i] !== 10 || px[i + 1] !== 20 || px[i + 2] !== 30 || px[i + 3] !== 255) changed++;
    }
    return changed; // pixels (of 64) that differ from what we painted
  }

  async function collectCanvas() {
    const first = safe(drawScene);
    if (!first) return { supported: false };
    const second = drawScene();
    return {
      supported: true,
      hash: await sha256(first),
      hash2: await sha256(second),
      probeChangedPixels: safe(canvasProbe),
    };
  }

  // ── WebGL ────────────────────────────────────────────────────────────────
  /** @param {any} gl */
  function webglInfo(gl) {
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const range = (/** @type {number} */ p) => Array.from(gl.getParameter(p) || []);
    return {
      supported: true,
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
      unmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
      version: gl.getParameter(gl.VERSION),
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      maxViewportDims: range(gl.MAX_VIEWPORT_DIMS),
      aliasedLineWidthRange: range(gl.ALIASED_LINE_WIDTH_RANGE),
      maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
      extensions: (gl.getSupportedExtensions() || []).slice().sort(),
    };
  }

  function collectWebGL() {
    return safe(() => {
      const gl = document.createElement("canvas").getContext("webgl");
      return gl ? webglInfo(gl) : { supported: false };
    }, { supported: false });
  }

  // ── audio ────────────────────────────────────────────────────────────────
  // OfflineAudioContext renders without a speaker and without the autoplay
  // policy (a live AudioContext stays suspended until a user gesture).
  async function collectAudio() {
    const w = /** @type {any} */ (window);
    const OAC = w.OfflineAudioContext || w.webkitOfflineAudioContext;
    if (!OAC) return { supported: false };
    try {
      const ctx = new OAC(1, 5000, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50;
      comp.knee.value = 40;
      comp.ratio.value = 12;
      comp.attack.value = 0;
      comp.release.value = 0.25;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const buffer = await Promise.race([
        ctx.startRendering(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1000)),
      ]);
      const data = buffer.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      return { supported: true, sum: Number(sum.toFixed(6)), hash: await sha256(String(sum)) };
    } catch (e) {
      return { supported: false, error: String(e) };
    }
  }

  // ── fonts ────────────────────────────────────────────────────────────────
  const FONT_PROBES = [
    // Windows
    "Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma", "Candara", "Franklin Gothic Medium",
    // macOS / iOS
    "Helvetica Neue", "Menlo", "Avenir", "Gill Sans", "Optima", "Futura", "Apple Color Emoji",
    // Linux
    "DejaVu Sans", "Liberation Sans", "Ubuntu", "Noto Sans", "Cantarell", "Droid Sans",
    // Common / office
    "Arial", "Times New Roman", "Courier New", "Georgia", "Verdana", "Trebuchet MS",
    "Comic Sans MS", "Impact", "Palatino", "Garamond",
  ];

  function collectFonts() {
    const ctx = /** @type {CanvasRenderingContext2D} */ (
      document.createElement("canvas").getContext("2d"));
    const text = "mmmmmmmmmmlli1WQ";
    const bases = ["monospace", "sans-serif", "serif"];
    /** @type {Record<string, number>} */
    const baseWidth = {};
    for (const b of bases) {
      ctx.font = `72px ${b}`;
      baseWidth[b] = ctx.measureText(text).width;
    }
    return FONT_PROBES.filter((font) => bases.some((b) => {
      ctx.font = `72px '${font}', ${b}`;
      return ctx.measureText(text).width !== baseWidth[b];
    }));
  }

  // ── voices ───────────────────────────────────────────────────────────────
  // Chrome loads the voice list asynchronously, so wait briefly for it.
  async function collectVoices() {
    const synth = window.speechSynthesis;
    if (!synth) return { supported: false, count: 0, hash: null, local: 0 };
    let voices = synth.getVoices();
    if (!voices.length) {
      await new Promise((resolve) => {
        synth.addEventListener("voiceschanged", resolve, { once: true });
        setTimeout(resolve, 300);
      });
      voices = synth.getVoices();
    }
    const names = voices.map((v) => `${v.name}|${v.lang}|${v.localService ? 1 : 0}`).sort();
    return {
      supported: true,
      count: voices.length,
      local: voices.filter((v) => v.localService).length,
      hash: names.length ? await sha256(names.join(",")) : null,
    };
  }

  // ── worker scope ─────────────────────────────────────────────────────────
  // Spoofing scripts that patch `navigator` in the page often never reach a
  // worker, which has its own navigator built from the real engine values.
  function collectWorker() {
    // Two messages: navigator values first (fast), then the worker's own WebGL
    // renderer, which can take >1 s in some engines. We wait briefly for it.
    const src = `
      const n = self.navigator;
      postMessage({
        phase: "nav",
        userAgent: n.userAgent,
        platform: n.platform,
        languages: Array.from(n.languages || []),
        hardwareConcurrency: n.hardwareConcurrency ?? null,
        deviceMemory: n.deviceMemory ?? null,
        uadPlatform: n.userAgentData ? n.userAgentData.platform : null,
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
      let webgl = null;
      try {
        const gl = new OffscreenCanvas(1, 1).getContext("webgl");
        if (gl) {
          const d = gl.getExtension("WEBGL_debug_renderer_info");
          webgl = d ? gl.getParameter(d.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        }
      } catch (e) {}
      postMessage({ phase: "gl", webglRenderer: webgl });`;
    return new Promise((resolve) => {
      /** @type {any} */
      let result = null;
      /** @type {Worker | null} */
      let worker = null;
      const finish = (/** @type {any} */ value) => {
        if (worker) worker.terminate();
        resolve(value);
      };
      try {
        const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
        worker = new Worker(url);
        let timer = setTimeout(() => finish({ error: "timeout" }), 1000);
        worker.onmessage = (e) => {
          if (e.data.phase === "nav") {
            result = { ...e.data, webglRenderer: null };
            delete result.phase;
            clearTimeout(timer);
            timer = setTimeout(() => finish(result), 400);
          } else {
            clearTimeout(timer);
            finish({ ...result, webglRenderer: e.data.webglRenderer });
          }
        };
        worker.onerror = () => { clearTimeout(timer); finish({ error: "worker error" }); };
      } catch (e) {
        finish({ error: String(e) });
      }
    });
  }

  // ── lie detection: the shape of patched natives ──────────────────────────
  // A native getter or method: its source reads "[native code]", it has no
  // `prototype` property, and it cannot be called with `new`. Spoofers fix
  // the first (by patching Function.prototype.toString) far more often than
  // the other two.
  /** @param {any} fn */
  function nativeShape(fn) {
    if (typeof fn !== "function") return { present: false };
    const src = safe(() => Function.prototype.toString.call(fn), "");
    let constructible = false;
    try {
      // Reflect.construct with a native method throws "is not a constructor"
      Reflect.construct(String, [], fn);
      constructible = true;
    } catch (e) {
      constructible = false;
    }
    return {
      present: true,
      nativeSource: /\{\s*\[native code\]\s*\}\s*$/.test(src || ""),
      hasPrototype: Object.prototype.hasOwnProperty.call(fn, "prototype"),
      constructible,
    };
  }

  function collectLies() {
    const getters = ["platform", "hardwareConcurrency", "deviceMemory", "userAgent",
                     "languages", "maxTouchPoints", "webdriver"];
    /** @type {Record<string, any>} */
    const navGetters = {};
    for (const name of getters) {
      const d = Object.getOwnPropertyDescriptor(Navigator.prototype, name);
      navGetters[name] = d ? nativeShape(d.get) : { present: false };
    }
    const methods = {
      "WebGLRenderingContext.getParameter": WebGLRenderingContext.prototype.getParameter,
      "HTMLCanvasElement.toDataURL": HTMLCanvasElement.prototype.toDataURL,
      "CanvasRenderingContext2D.getImageData": CanvasRenderingContext2D.prototype.getImageData,
      "Function.toString": Function.prototype.toString,
    };
    /** @type {Record<string, any>} */
    const methodShapes = {};
    for (const [name, fn] of Object.entries(methods)) methodShapes[name] = nativeShape(fn);
    return {
      // Properties defined directly on the navigator object instead of its prototype
      navigatorOwnProps: Object.getOwnPropertyNames(navigator),
      navGetters,
      methods: methodShapes,
    };
  }

  // ── assemble and send ────────────────────────────────────────────────────
  async function collect() {
    const started = performance.now();
    const [uad, canvas, audio, voices, worker] = await Promise.all([
      collectUserAgentData(), collectCanvas(), collectAudio(), collectVoices(), collectWorker(),
    ]);
    const payload = {
      v: 1,
      nonce: /** @type {any} */ (window).__fpNonce || null,
      nav: collectNavigator(),
      uad,
      screen: collectScreen(),
      intl: collectIntl(),
      canvas,
      webgl: collectWebGL(),
      audio,
      fonts: collectFonts(),
      voices,
      worker,
      lies: collectLies(),
      collect_ms: 0,
    };
    payload.collect_ms = Math.round(performance.now() - started);
    return payload;
  }

  async function send() {
    const payload = await collect();
    const w = /** @type {any} */ (window);
    w.__fp = payload;
    try {
      const r = await fetch("/api/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "fp", ...payload }),
        credentials: "same-origin",
      });
      w.__fpResult = await r.json();
    } catch (e) {
      w.__fpResult = { error: String(e) };
    }
    document.dispatchEvent(new CustomEvent("fp:done", { detail: w.__fpResult }));
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", send);
  } else {
    send();
  }
})();
