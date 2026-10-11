/*
 * Chapter 7: the page side of the PoW gate.
 *
 *   interstitial   the gate's 403 page: solve its payload, POST the answer, reload the page
 *   gatedFetch()   fetch; on a JSON `challenge_required` (pow) solve, verify, retry once
 *   ensurePass()   solve a payload (or GET /api/challenge?type=pow) -> POST /api/challenge/verify
 *   powBenchmark() hashes per second for N workers (the /lab/pow/bench page)
 *
 * The solver fans out across up to 4 workers, each trying every Nth counter.
 * A real user never sees anything but a short "Checking your browser..." line.
 * A user without JavaScript sees nothing at all, and that is a cost.
 */

const POW_WORKERS = Math.min(navigator.hardwareConcurrency || 2, 4);
window.powStats = { solves: [] };  // read by attacks/round5_playwright_browser.py

function setStatus(text) {
  const el = document.getElementById("pow-status");
  if (el) el.textContent = text;
}

function solveChallenge(nonce, bits) {
  return new Promise((resolve) => {
    const workers = [];
    for (let i = 0; i < POW_WORKERS; i++) {
      const w = new Worker("/static/js/pow-worker.js");
      w.onmessage = (e) => {
        workers.forEach(x => x.terminate());
        // the others ran about as long as the winner did
        resolve({ counter: e.data.counter, tried: e.data.tried * POW_WORKERS });
      };
      w.postMessage({ cmd: "solve", nonce, bits, start: i, step: POW_WORKERS });
      workers.push(w);
    }
  });
}

let inflight = null;  // single flight: parallel 403s share one solve

function ensurePass(payload) {
  if (!inflight) {
    inflight = (async () => {
      const challenge = payload || (await (await fetch("/api/challenge?type=pow")).json()).payload;
      setStatus(`Checking your browser… (difficulty ${challenge.difficulty} bits)`);
      const started = performance.now();
      const { counter, tried } = await solveChallenge(challenge.nonce, challenge.difficulty);
      const ms = performance.now() - started;
      const r = await fetch("/api/challenge/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "pow", answer: { challenge, counter } }),
      });
      window.powStats.solves.push({ bits: challenge.difficulty, ms, tried, ok: r.ok });
      setStatus(r.ok ? `Verified in ${ms.toFixed(0)} ms (${challenge.difficulty} bits)`
                     : "Verification failed. Please reload.");
      return r.ok;
    })().finally(() => { inflight = null; });
  }
  return inflight;
}

async function gatedFetch(url, options) {
  let r = await fetch(url, options);
  if (r.status === 403) {
    const body = await r.clone().json().catch(() => ({}));
    const err = body.error || {};
    if (err.code === "challenge_required" && err.challenge === "pow" && await ensurePass(err.payload)) {
      r = await fetch(url, options);
    }
  }
  return r;
}

function powBenchmark(workers, ms) {
  return Promise.all(Array.from({ length: workers }, () => new Promise((resolve) => {
    const w = new Worker("/static/js/pow-worker.js");
    w.onmessage = (e) => { w.terminate(); resolve(e.data.tried / (e.data.ms / 1000)); };
    w.postMessage({ cmd: "bench", ms });
  }))).then(rates => rates.reduce((a, b) => a + b, 0));
}

document.addEventListener("DOMContentLoaded", () => {
  const gate = document.querySelector('[data-challenge="pow"]');
  if (gate) {                                            // the gate's interstitial
    const payload = JSON.parse(document.getElementById("pow-payload").textContent);
    ensurePass(payload).then(ok => { if (ok) location.replace(gate.dataset.next); });
  }
  const go = document.getElementById("pow-bench-go");
  if (go) {                                              // /lab/pow/bench
    go.onclick = async () => {
      const out = document.getElementById("pow-bench-out");
      out.innerHTML = "";
      for (const workers of [1, Math.min(navigator.hardwareConcurrency || 2, 4)]) {
        const rate = await powBenchmark(workers, 3000);
        // geometric distribution: p50 = 0.69 * 2^16, p95 = 3.0 * 2^16 hashes
        const t = h => (h / rate * 1000).toFixed(0) + " ms";
        out.innerHTML += `<tr><td>${workers}</td><td>${(rate / 1e6).toFixed(2)}</td><td>${t(45426)}</td><td>${t(196327)}</td></tr>`;
        fetch("/api/telemetry", { method: "POST", headers: { "Content-Type": "application/json" },
                                  body: JSON.stringify({ kind: "pow_bench", workers, mhs: rate / 1e6 }) });
      }
    };
  }
});
