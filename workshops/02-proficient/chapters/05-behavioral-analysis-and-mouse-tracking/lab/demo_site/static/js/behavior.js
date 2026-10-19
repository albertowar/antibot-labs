// @ts-check
/**
 * Chapter 5: behavioral telemetry collector (Section 3.2).
 *
 * Records HOW the visitor interacts with the drop page: pointer paths, clicks,
 * keystroke *timing* and form-fill events. Plain JavaScript, no build step,
 * no dependencies. Type-checked by editors through the @ts-check comment.
 *
 * Privacy by design:
 *   - We never send key values or `event.code`. A keystroke becomes a coarse
 *     class ("c" = character, "b" = backspace, ...) plus its press and release
 *     times. Logging `code` on a password field would be a keylogger.
 *   - Coordinates are page pixels, times are milliseconds since navigation.
 *
 * Delivery: when the reservation form is submitted, the record goes to
 * POST /api/telemetry {"kind": "behavior", ...} first, then the form is sent.
 * The server scores it when the form arrives (defenses/behavior_l1..l5.py).
 *
 * Trade-offs:
 *   - Everything here runs on the attacker's machine. A bot can skip this
 *     script and POST a forged payload. Protecting the sensor (obfuscation,
 *     integrity tokens) is Chapter 4's topic; this chapter is about what the
 *     data says once you have it.
 *   - Raw coalesced pointer samples are the richest signal and the biggest
 *     cost: a 1000 Hz gaming mouse produces 10x the payload of a 125 Hz one.
 *     MAX_POINTS caps it; the checkpoint reports telemetry KB per session.
 */
(function () {
  "use strict";

  const MAX_POINTS = 6000;
  const KEY_CLASS = /** @type {Record<string, string>} */ ({
    Backspace: "b", Delete: "b", Tab: "t", Enter: "e",
    Shift: "m", Control: "m", Alt: "m", Meta: "m", CapsLock: "m",
    ArrowLeft: "n", ArrowRight: "n", ArrowUp: "n", ArrowDown: "n",
    Home: "n", End: "n", Unidentified: "u", Process: "u",
  });

  /** @param {number} v */
  const r1 = (v) => Math.round(v * 10) / 10;

  /** The logical field an event hit: the nearest [data-field], else the element id or tag.
   * @param {EventTarget | null} target */
  function fieldOf(target) {
    const el = /** @type {HTMLElement | null} */ (target);
    if (!el || !el.tagName) return "";
    const tagged = /** @type {HTMLElement | null} */ (el.closest("[data-field]"));
    return (tagged && tagged.dataset.field) || el.id || el.tagName.toLowerCase();
  }

  /** Page offset of the form the server laid out: its boxes are relative to its padding box. */
  function formOrigin() {
    const f = document.getElementById("behavior-form");
    if (!f) return [0, 0];
    const r = f.getBoundingClientRect();
    return [r1(r.left + f.clientLeft + window.scrollX), r1(r.top + f.clientTop + window.scrollY)];
  }

  /** @param {string} pointerType */
  function kindOf(pointerType) {
    if (pointerType === "touch") return "t";
    if (pointerType === "pen") return "p";
    if (pointerType === "mouse") return "m";
    return "";
  }

  const data = {
    v: 1,
    viewport: [window.innerWidth, window.innerHeight],
    dpr: window.devicePixelRatio,
    doc_h: 0,
    /** @type {Array<[number, number, number, string]>} t, x, y, kind */
    pointer: [],
    moves_dispatched: 0,
    /** @type {Array<[number, number, number, string, number]>} t, x, y, kind, button */
    downs: [],
    /** @type {Array<[number, number, number, string]>} t, x, y, kind */
    ups: [],
    /** @type {Array<[number, number, number, number, string]>} t, width, height, pressure, kind (logged, not scored) */
    contact: [],
    /** @type {[number, number]} page offset of #behavior-form */
    origin: [0, 0],
    /** @type {Array<[number, number, number, number, string, string, boolean]>} t, x, y, detail, target, kind, isTrusted */
    clicks: [],
    /** @type {Array<[string, number, number | null, string]>} field, down_t, up_t, class */
    keys: [],
    /** @type {Array<[number, string, string | null, boolean]>} t, field, inputType, had_key */
    inputs: [],
    /** @type {Array<[number, string]>} t, field */
    focus: [],
    /** @type {Array<[number, number]>} t, scrollY */
    scroll: [],
    t_submit: 0,
  };

  // ── Pointer: every raw sample, including the ones the browser coalesced ──
  document.addEventListener("pointermove", (ev) => {
    data.moves_dispatched += 1;
    const samples = typeof ev.getCoalescedEvents === "function" ? ev.getCoalescedEvents() : [];
    const list = samples.length ? samples : [ev];
    for (const s of list) {
      if (data.pointer.length >= MAX_POINTS) return;
      data.pointer.push([r1(s.timeStamp), r1(s.pageX), r1(s.pageY), kindOf(s.pointerType)]);
    }
  }, { passive: true });

  document.addEventListener("pointerdown", (ev) => {
    data.downs.push([r1(ev.timeStamp), r1(ev.pageX), r1(ev.pageY), kindOf(ev.pointerType), ev.button]);
    data.contact.push([r1(ev.timeStamp), r1(ev.width), r1(ev.height), Math.round(ev.pressure * 100) / 100,
                       kindOf(ev.pointerType)]);
  }, { passive: true });

  document.addEventListener("pointerup", (ev) => {
    data.ups.push([r1(ev.timeStamp), r1(ev.pageX), r1(ev.pageY), kindOf(ev.pointerType)]);
  }, { passive: true });

  document.addEventListener("click", (ev) => {
    // In Chromium and Firefox `click` is a PointerEvent; pointerType is ""
    // when the keyboard (Enter/Space) activated the element, and detail is 0.
    const pe = /** @type {PointerEvent} */ (ev);
    data.clicks.push([r1(ev.timeStamp), r1(ev.pageX), r1(ev.pageY), ev.detail,
                      fieldOf(ev.target), kindOf(pe.pointerType || ""), ev.isTrusted]);
  }, true);

  // ── Keyboard: timing only, never the key ──
  /** @type {Map<string, number>} */
  const open = new Map();
  let lastKeyT = -1;
  let lastKeyField = "";

  document.addEventListener("keydown", (ev) => {
    if (ev.repeat) return;
    const cls = KEY_CLASS[ev.key] || (ev.key.length === 1 ? "c" : "o");
    data.keys.push([fieldOf(ev.target), r1(ev.timeStamp), null, cls]);
    open.set(ev.code || ev.key, data.keys.length - 1);   // pairing only, not sent
    lastKeyT = ev.timeStamp;
    lastKeyField = fieldOf(ev.target);
  }, true);

  document.addEventListener("keyup", (ev) => {
    const idx = open.get(ev.code || ev.key);
    if (idx === undefined) return;
    data.keys[idx][2] = r1(ev.timeStamp);
    open.delete(ev.code || ev.key);
  }, true);

  // ── Form fills: typed, pasted, autofilled or injected? ──
  document.addEventListener("input", (ev) => {
    const ie = /** @type {InputEvent} */ (ev);
    const field = fieldOf(ev.target);
    const hadKey = field === lastKeyField && ev.timeStamp - lastKeyT < 50;
    data.inputs.push([r1(ev.timeStamp), field, ie.inputType || null, hadKey]);
  }, true);

  document.addEventListener("focus", (ev) => {
    data.focus.push([r1(ev.timeStamp), fieldOf(ev.target)]);
  }, true);

  let lastScroll = 0;
  window.addEventListener("scroll", () => {
    const t = performance.now();
    if (t - lastScroll < 50) return;   // throttle: scroll fires per frame
    lastScroll = t;
    data.scroll.push([r1(t), Math.round(window.scrollY)]);
  }, { passive: true });

  /** Freeze the record at submit time. */
  function snapshot() {
    data.t_submit = r1(performance.now());
    data.doc_h = document.documentElement.scrollHeight;
    data.origin = formOrigin();
    return JSON.parse(JSON.stringify(data));
  }

  // ── Delivery: telemetry first, then the form ──
  const form = /** @type {HTMLFormElement | null} */ (document.querySelector("form.buy"));
  if (form) {
    data.origin = formOrigin();
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        await fetch("/api/telemetry", {
          method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
          body: JSON.stringify(Object.assign({ kind: "behavior" }, snapshot())),
        });
      } catch (e) { /* no telemetry is a signal too; send the form anyway */ }
      form.submit();     // the native submit does not fire this listener again
    });
  }

  /** @type {any} */ (window).behaviorCollector = { snapshot };
})();
