/*
 * Chapter 4 — Round 3 exercise: how long does obfuscation hold?
 *
 * Downloads the variant the server hands out right now and runs webcrack
 * (MIT, local, no upload to a third-party site) over it. webcrack undoes
 * the transforms javascript-obfuscator applies: string-array decoding (rc4
 * included), control-flow-flattening, dead code, self-defending wrappers.
 *
 * Usage:
 *   npm run deobfuscate                         # http://127.0.0.1:5000
 *   DEMO_URL=http://127.0.0.1:5050 npm run deobfuscate
 *
 * Writes attacks/out/<variant>.obf.js and attacks/out/<variant>.deobf.js.
 * Open the .deobf.js and find step(): the variant's op chain is right there.
 *
 * Then ask yourself: does reading it help? You could port this variant, but
 * the next challenge uses another one. Automating the extraction is the
 * bonus challenge. Running it instead is Round 3's attack.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { webcrack } from "webcrack";

const base = process.env.DEMO_URL || "http://127.0.0.1:5000";
if (!["localhost", "127.0.0.1", "::1"].includes(new URL(base).hostname)) {
  console.error("Refusing: lab attacks only target localhost.");
  process.exit(2);
}

// The catalogue answers with the 403 interstitial, which embeds the signed challenge.
const page = await fetch(`${base}/products`, { headers: { Accept: "text/html", "X-Lab-Actor": "bot:deobfuscate" } });
const m = (await page.text()).match(/window\.__ch = (\{.*?\});/);
const ch = m ? JSON.parse(m[1]) : {};
if (!ch.script) {
  console.error("No challenge script at this level (needs level 2 or above).");
  process.exit(1);
}
const source = await (await fetch(new URL(ch.script, base))).text();
const name = ch.script.split("/").pop().replace(".js", "");

const t0 = performance.now();
const result = await webcrack(source);
const ms = performance.now() - t0;

mkdirSync("attacks/out", { recursive: true });
writeFileSync(`attacks/out/${name}.obf.js`, source);
writeFileSync(`attacks/out/${name}.deobf.js`, result.code);
console.log(`variant ${name}: ${source.length} bytes obfuscated -> ${result.code.length} bytes after webcrack, in ${ms.toFixed(0)} ms`);
console.log(`read it:  attacks/out/${name}.deobf.js   (look for the function with the '>>> 0' lines)`);
