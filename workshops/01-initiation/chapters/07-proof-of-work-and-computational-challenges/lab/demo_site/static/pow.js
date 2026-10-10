/*
 * Chapter 7: the page side of the PoW gate.
 *
 *   gatedFetch(url)  fetch; on a 403 {"error": "pow_required"} get a pass, then retry once
 *   ensurePass()     GET /pow/challenge -> solve in Web Workers -> POST /pow/verify
 *   powBenchmark()   hashes per second for N workers (the /pow-bench page)
 *
 * The solver fans out across up to 4 workers, each trying every Nth counter.
 * A real user never sees anything but a short "Checking your browser..." line.
 * A user without JavaScript sees nothing at all, and that is a cost.
 */

const POW_WORKERS = Math.min(navigator.hardwareConcurrency || 2, 4);
window.powStats = { solves: [] };  // read by attacks/round5_playwright_browser.py

function setStatus(text) {
  const el = document.getElementById("pow");
  if (el) el.textContent = text;
}

function solveChallenge(nonce, bits) {
  return new Promise((resolve) => {
    const workers = [];
    for (let i = 0; i < POW_WORKERS; i++) {
      const w = new Worker("/static/pow-worker.js");
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

function ensurePass() {
  if (!inflight) {
    inflight = (async () => {
      const challenge = await (await fetch("/pow/challenge")).json();
      setStatus(`Checking your browser… (difficulty ${challenge.difficulty} bits)`);
      const started = performance.now();
      const { counter, tried } = await solveChallenge(challenge.nonce, challenge.difficulty);
      const ms = performance.now() - started;
      const r = await fetch("/pow/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge, counter }),
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
    if (body.error === "pow_required" && await ensurePass()) r = await fetch(url, options);
  }
  return r;
}

function powBenchmark(workers, ms) {
  return Promise.all(Array.from({ length: workers }, () => new Promise((resolve) => {
    const w = new Worker("/static/pow-worker.js");
    w.onmessage = (e) => { w.terminate(); resolve(e.data.tried / (e.data.ms / 1000)); };
    w.postMessage({ cmd: "bench", ms });
  }))).then(rates => rates.reduce((a, b) => a + b, 0));
}
