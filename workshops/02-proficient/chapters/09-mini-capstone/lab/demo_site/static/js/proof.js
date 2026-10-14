/*
 * Capstone: the page side of the "proof" challenge. On the gate's interstitial, find a counter so that
 * sha256(nonce:counter) has `bits` leading zero bits, POST it to /api/challenge/verify, and go back to
 * the page the customer came from. Plain ES2020; a customer sees one status line for well under a second.
 */
(function () {
  "use strict";
  const box = document.querySelector("[data-challenge='proof']");
  const payloadEl = document.getElementById("proof-payload");
  if (!box || !payloadEl) return;
  const payload = JSON.parse(payloadEl.textContent);
  const status = document.getElementById("proof-status");

  async function leadingZeroBits(text) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    let bits = 0;
    for (const b of d) {
      if (b === 0) { bits += 8; continue; }
      return bits + Math.clz32(b) - 24;
    }
    return bits;
  }

  async function solve() {
    for (let counter = 0; ; counter++) {
      if (await leadingZeroBits(payload.nonce + ":" + counter) >= payload.bits) return counter;
    }
  }

  solve().then(async (counter) => {
    const r = await fetch("/api/challenge/verify", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "proof", answer: { nonce: payload.nonce, counter } }),
    });
    status.textContent = r.ok ? "Verified. Taking you back to the drop." : "Verification failed. Please reload.";
    if (r.ok) setTimeout(() => { location.href = box.dataset.next || "/"; }, 400);
  });
})();
