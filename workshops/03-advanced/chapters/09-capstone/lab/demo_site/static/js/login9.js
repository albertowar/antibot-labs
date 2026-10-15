/*
 * Capstone Round 4: the login page's half of the token flow (defenses/token_binding.py).
 * On submit: wait for the sensor report to land, GET /api/login/challenge, find a counter with
 * sha256(nonce:fp_hash:counter) starting with `bits` zero bits, POST it to /api/login/token, put the token
 * in the form's hidden field and submit for real. Client code is never a secret: anyone can read this and
 * re-implement it, which is exactly what attacks/round4_stuffing.py --with-token does.
 */
(function () {
  "use strict";
  const form = document.getElementById("login-form");
  if (!form) return;
  let busy = false;

  async function zeroBits(text) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    let bits = 0;
    for (const b of d) {
      if (b === 0) { bits += 8; continue; }
      return bits + Math.clz32(b) - 24;
    }
    return bits;
  }

  async function getToken() {
    let r = null;
    for (let i = 0; i < 10; i++) {            // the sensor posts its report as the page loads
      r = await fetch("/api/login/challenge");
      if (r.ok) break;
      await new Promise((res) => setTimeout(res, 300));
    }
    if (!r || !r.ok) return "";
    const c = await r.json();
    let counter = 0;
    while (await zeroBits(`${c.nonce}:${c.fp_hash}:${counter}`) < c.bits) counter++;
    const t = await fetch("/api/login/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: c.nonce, counter }),
    });
    return t.ok ? (await t.json()).token : "";
  }

  form.addEventListener("submit", async (e) => {
    if (busy) return;
    e.preventDefault();
    busy = true;
    form.elements.login_token.value = await getToken();
    form.submit();
  });
})();
