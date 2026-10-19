// Round 2 attacker: a stealth-plugin-style init script.
//
// Runs before any page script (Playwright add_init_script) and rewrites
// what the page can read, using the same trick as puppeteer-extra's stealth
// evasions: wrap the native getter or method in a Proxy. A Proxy around a
// native function still prints "[native code]", has no `prototype` and
// can't be constructed, so shape checks can't tell it apart.
//
// What it forgets (on purpose, like most real patch sets): Web Workers get
// their own navigator and WebGL, and HTTP headers are written by the
// network stack, not by page JavaScript.
(() => {
  const spoofGetter = (proto, prop, fn) => {
    const desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) return;
    const get = new Proxy(desc.get, { apply: (target, self, args) => fn(Reflect.apply(target, self, args)) });
    Object.defineProperty(proto, prop, { ...desc, get });
  };
  const spoofMethod = (proto, name, fn) => {
    proto[name] = new Proxy(proto[name], { apply: (target, self, args) => fn(target, self, args) });
  };

  // A mid-range Windows gaming PC
  spoofGetter(Navigator.prototype, "platform", () => "Win32");
  spoofGetter(Navigator.prototype, "hardwareConcurrency", () => 8);
  spoofGetter(Navigator.prototype, "deviceMemory", () => 8);

  // Hide SwiftShader behind an NVIDIA renderer string
  const UNMASKED_VENDOR = 0x9245, UNMASKED_RENDERER = 0x9246;
  for (const ctx of [WebGLRenderingContext, WebGL2RenderingContext]) {
    spoofMethod(ctx.prototype, "getParameter", (target, self, args) => {
      if (args[0] === UNMASKED_VENDOR) return "Google Inc. (NVIDIA)";
      if (args[0] === UNMASKED_RENDERER) {
        return "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)";
      }
      return Reflect.apply(target, self, args);
    });
  }

  // Rename the HeadlessChrome brand in navigator.userAgentData
  if (self.NavigatorUAData) {
    spoofGetter(NavigatorUAData.prototype, "brands", (brands) =>
      brands.map((b) => (b.brand === "HeadlessChrome" ? { brand: "Google Chrome", version: b.version } : b)));
  }

  // Windows always ships speech voices; headless Linux has none
  if (self.speechSynthesis) {
    const voices = ["Microsoft David - English (United States)", "Microsoft Mark - English (United States)",
                    "Microsoft Zira - English (United States)"]
      .map((name, i) => ({ name, lang: "en-US", localService: true, default: i === 0, voiceURI: name }));
    spoofMethod(SpeechSynthesis.prototype, "getVoices", () => voices);
  }
})();
