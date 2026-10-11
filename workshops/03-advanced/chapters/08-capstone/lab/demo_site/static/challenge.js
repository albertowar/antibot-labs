/*
 * Chapter 9 — Login token challenge (Section 9.5, Round 4)
 *
 * Before a login is accepted at DEFENSE_LEVEL 4, the page must:
 *   1. send its telemetry, so the server knows this session's fingerprint hash
 *   2. fetch a nonce and solve a small proof of work bound to the session id
 *      and that fingerprint hash
 *   3. trade the solution for a short-lived HMAC token, sent with the login
 *
 * What it buys: a login request is now proof that *something* ran this page's
 * JavaScript in this session in the last two minutes. A bare HTTP stuffer
 * (curl_cffi, httpx) gets nothing.
 *
 * What it does not buy: secrecy. This file is readable, so an attacker can
 * re-implement it in Python in an afternoon (W2 Ch2). The token raises cost
 * and forces every attempt through one session and one fingerprint, which is
 * what makes the per-cluster failure ratio in login_risk.py work.
 */
window.labChallenge = (function () {
  "use strict";

  function leadingZeroBits(bytes) {
    let bits = 0;
    for (const b of bytes) {
      if (b === 0) { bits += 8; continue; }
      return bits + Math.clz32(b) - 24;
    }
    return bits;
  }

  async function solve(nonce, fpHash, difficulty) {
    const enc = new TextEncoder();
    for (let counter = 0; ; counter++) {
      const digest = await crypto.subtle.digest("SHA-256", enc.encode(`${nonce}:${fpHash}:${counter}`));
      if (leadingZeroBits(new Uint8Array(digest)) >= difficulty) return counter;
    }
  }

  async function token() {
    const telemetry = await window.labTelemetry.flush();
    const c = await (await fetch("/api/challenge", { credentials: "same-origin" })).json();
    const started = performance.now();
    const counter = await solve(c.nonce, telemetry.fp_hash, c.difficulty);
    const r = await fetch("/api/challenge/verify", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: c.nonce, counter, solve_ms: Math.round(performance.now() - started) }),
    });
    return (await r.json()).token;
  }

  return { token };
})();
