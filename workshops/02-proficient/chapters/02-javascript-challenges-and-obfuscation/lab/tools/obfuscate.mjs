/*
 * Chapter 2 — Obfuscate challenge variants with javascript-obfuscator (Round 3)
 *
 * Called by tools/build_variants.py:
 *   node tools/obfuscate.mjs <src_dir> <out_dir>
 *
 * Prints one JSON line per file: {"id", "bytes_in", "bytes_out", "ms"}.
 *
 * The options are the ones a defender would really pick, and why:
 *   stringArray + rc4        hides 'challenge/verify', 'offsetWidth', ...
 *   controlFlowFlattening    turns the op chain into a switch-in-a-loop
 *   deadCodeInjection        adds decoy branches (and bytes)
 *   numbersToExpressions     hides the chain's constants
 *   selfDefending            breaks the code if it is reformatted and re-run
 *
 * Deliberately OFF:
 *   debugProtection          spins the CPU while DevTools is open. It hurts your
 *                            own support staff and real users with DevTools open
 *                            more than it slows an attacker, who just runs the
 *                            code outside a browser.
 *   domainLock               adds little against a scraper that runs on your own origin.
 *
 * TODO (Round 3, optional): set controlFlowFlattening and deadCodeInjection to
 * false, rebuild (python tools/build_variants.py), then compare the KB and the
 * webcrack output (npm run deobfuscate). What did those two options buy you?
 *
 * Note the 'ms' column: obfuscating costs tens to hundreds of milliseconds per
 * file. Doing it per request puts that on every challenge. Build a pool ahead
 * of time and rotate it instead.
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, basename } from "node:path";
import JavaScriptObfuscator from "javascript-obfuscator";

const OPTIONS = {
  compact: true,
  target: "browser",
  identifierNamesGenerator: "hexadecimal",
  stringArray: true,
  stringArrayEncoding: ["rc4"],
  stringArrayThreshold: 1,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  splitStrings: true,
  splitStringsChunkLength: 5,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.75,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
  numbersToExpressions: true,
  selfDefending: true,
  debugProtection: false,
  disableConsoleOutput: false,
};

const [srcDir, outDir] = process.argv.slice(2);
if (!srcDir || !outDir) {
  console.error("usage: node tools/obfuscate.mjs <src_dir> <out_dir>");
  process.exit(2);
}
mkdirSync(outDir, { recursive: true });

for (const file of readdirSync(srcDir).filter((f) => f.endsWith(".js")).sort()) {
  const source = readFileSync(join(srcDir, file), "utf8");
  const t0 = performance.now();
  const code = JavaScriptObfuscator.obfuscate(source, OPTIONS).getObfuscatedCode();
  const ms = performance.now() - t0;
  writeFileSync(join(outDir, file), code);
  console.log(JSON.stringify({
    id: basename(file, ".js"), bytes_in: source.length, bytes_out: code.length, ms: Math.round(ms),
  }));
}
