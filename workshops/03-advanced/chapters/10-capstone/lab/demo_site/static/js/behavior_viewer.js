// @ts-check
/**
 * Chapter 3: trace viewer for /lab/behavior/view/<sid> (Round 0).
 *
 * Draws one session: the layout boxes, the pointer path (darker = faster),
 * clicks and taps, the closing-speed profile of each approach, and a keystroke
 * timeline. The path is scaled to fit the canvas. Read-only, debug only.
 */

/** @param {string} id */
function canvas2d(id) {
  const c = /** @type {HTMLCanvasElement} */ (document.getElementById(id));
  return { c, g: /** @type {CanvasRenderingContext2D} */ (c.getContext("2d")) };
}

const COLORS = ["#d62728", "#1f77b4", "#2ca02c", "#9467bd", "#ff7f0e", "#8c564b"];

/** @param {string} sid */
async function drawTrace(sid) {
  const r = await fetch(`/lab/behavior/trace/${encodeURIComponent(sid)}`);
  if (!r.ok) { document.body.insertAdjacentHTML("beforeend", "<p>Trace not found.</p>"); return; }
  const trace = await r.json();
  const tel = trace.telemetry, f = trace.features, d = trace.decision;
  /** @type {HTMLElement} */ (document.getElementById("meta")).textContent =
    `level ${trace.level} · ${d ? `${d.action} (score ${d.score}) ${d.signals}` : "no reservation yet"} · ` +
    `${tel.pointer.length} pointer samples · ${tel.keys.length} keys`;

  // ── path (page coordinates, scaled to fit) ──
  const { c, g } = canvas2d("path");
  const xs = [], ys = [];
  for (const b of Object.values(trace.layout.boxes)) { xs.push(b[0], b[0] + b[2]); ys.push(b[1], b[1] + b[3]); }
  for (const p of tel.pointer) { xs.push(p[1]); ys.push(p[2]); }
  const x0 = Math.min(...xs) - 20, y0 = Math.min(...ys) - 20;
  const k = Math.min(c.width / (Math.max(...xs) + 20 - x0), c.height / (Math.max(...ys) + 20 - y0), 2);
  g.setTransform(k, 0, 0, k, -x0 * k, -y0 * k);
  g.strokeStyle = "#bbb";
  for (const [name, b] of Object.entries(trace.layout.boxes)) {
    g.strokeRect(b[0], b[1], b[2], b[3]);
    g.fillStyle = "#999"; g.font = "12px sans-serif"; g.fillText(name, b[0] + 4, b[1] + 14);
  }
  const pts = tel.pointer;
  for (let i = 1; i < pts.length; i++) {
    const [t0, x0, y0] = pts[i - 1], [t1, x1, y1] = pts[i];
    const v = Math.hypot(x1 - x0, y1 - y0) / Math.max(1, t1 - t0);     // px/ms
    const shade = Math.max(0, 200 - Math.min(200, v * 120));
    g.strokeStyle = `rgb(${shade},${shade},255)`;
    g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke();
  }
  g.fillStyle = "#000";
  for (const p of pts) g.fillRect(p[1] - 0.5, p[2] - 0.5, 1, 1);
  if (pts.length) { g.fillStyle = "#2ca02c"; g.beginPath(); g.arc(pts[0][1], pts[0][2], 5, 0, 7); g.fill(); }
  g.strokeStyle = "#d62728"; g.lineWidth = 2;
  for (const c of tel.clicks) { g.beginPath(); g.arc(c[1], c[2], 7, 0, 7); g.stroke(); }
  g.lineWidth = 1;
  g.setTransform(1, 0, 0, 1, 0, 0);

  // ── closing speed per approach ──
  const sp = canvas2d("speed");
  const series = f.approaches.map((/** @type {any} */ a) => a.speeds);
  const vmax = Math.max(0.01, ...series.flat());
  const longest = Math.max(1, ...series.map((/** @type {number[]} */ s) => s.length));
  series.forEach((/** @type {number[]} */ s, i) => {
    sp.g.strokeStyle = COLORS[i % COLORS.length];
    sp.g.beginPath();
    s.forEach((v, k) => {
      const x = 40 + (k / longest) * (sp.c.width - 60), y = sp.c.height - 20 - (v / vmax) * (sp.c.height - 40);
      k ? sp.g.lineTo(x, y) : sp.g.moveTo(x, y);
    });
    sp.g.stroke();
    const a = f.approaches[i];
    sp.g.fillStyle = sp.g.strokeStyle;
    sp.g.fillText(`#${a.index}: end ${a.end_ratio} · straight ${a.straightness} · ${a.duration_ms} ms`, 50, 16 + 14 * i);
  });

  // ── keystrokes ──
  const kc = canvas2d("keys");
  const keys = tel.keys.filter((/** @type {any[]} */ k) => k[2] !== null);
  if (keys.length) {
    const t0 = keys[0][1], t1 = Math.max(...keys.map((/** @type {any[]} */ k) => k[2]));
    const scale = (kc.c.width - 20) / Math.max(1, t1 - t0);
    const fields = [...new Set(keys.map((/** @type {any[]} */ k) => k[0]))];
    keys.forEach((/** @type {any[]} */ k) => {
      const row = fields.indexOf(k[0]);
      kc.g.fillStyle = k[3] === "b" ? "#d62728" : COLORS[(row + 1) % COLORS.length];
      kc.g.fillRect(10 + (k[1] - t0) * scale, 10 + row * 34, Math.max(1, (k[2] - k[1]) * scale), 24);
    });
  }

  // ── features ──
  const shown = JSON.parse(JSON.stringify(f));
  shown.approaches.forEach((/** @type {any} */ a) => delete a.speeds);
  shown.signature = `${f.signature.paths.length} path + ${f.signature.keys.length} key entries`;
  /** @type {HTMLElement} */ (document.getElementById("feats")).textContent = JSON.stringify(shown, null, 2);
}

/** @type {any} */ (window).drawTrace = drawTrace;
