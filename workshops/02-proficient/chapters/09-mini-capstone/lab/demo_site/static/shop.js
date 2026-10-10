/*
 * Chapter 9 — Store page wiring
 *
 * Every protected action sends this page's telemetry first and then calls
 * the API. The result is written to #result with a data-outcome attribute
 * (allow / challenge / block / error), which the attack scripts and your
 * own eyes both read.
 */
(function () {
  "use strict";
  const level = Number(document.body.dataset.level || 0);
  const result = document.getElementById("result");

  function show(reply) {
    if (!result) return;
    result.dataset.outcome = reply.outcome || "error";
    result.textContent = reply.message || JSON.stringify(reply);
    if (reply.reasons && reply.reasons.length) {
      const ul = document.createElement("ul");
      for (const r of reply.reasons) { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); }
      result.appendChild(ul);
    }
  }

  async function post(url, body, extraHeaders) {
    const r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: Object.assign({ "Content-Type": "application/json" }, extraHeaders || {}),
      body: JSON.stringify(body),
    });
    try { return await r.json(); } catch (err) { return { outcome: "error", message: `HTTP ${r.status}` }; }
  }

  const buy = document.getElementById("buy");
  if (buy) {
    buy.addEventListener("click", async () => {
      buy.disabled = true;
      await window.labTelemetry.flush();
      show(await post("/api/buy", { sku: buy.dataset.sku }));
      buy.disabled = false;
    });
  }

  const login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", async (e) => {
      e.preventDefault();
      const headers = {};
      if (level >= 4) headers["X-Lab-Token"] = await window.labChallenge.token();
      else await window.labTelemetry.flush();
      const reply = await post("/api/login", {
        email: login.email.value, password: login.password.value,
      }, headers);
      show(reply);
      if (reply.outcome === "allow" && login.dataset.next) location.href = login.dataset.next;
    });
  }

  const register = document.getElementById("register-form");
  if (register) {
    register.addEventListener("submit", async (e) => {
      e.preventDefault();
      await window.labTelemetry.flush();
      const reply = await post("/api/register", {
        email: register.email.value, password: register.password.value, address: register.address.value,
      });
      show(reply);
      if (reply.outcome === "allow" && register.dataset.next) location.href = register.dataset.next;
    });
  }

  const capture = document.getElementById("capture");
  if (capture) {
    capture.addEventListener("click", async () => {
      await window.labTelemetry.flush();
      const r = await fetch("/lab/capture/profile", { credentials: "same-origin" });
      document.getElementById("profile").textContent = JSON.stringify(await r.json(), null, 2);
    });
  }
})();
