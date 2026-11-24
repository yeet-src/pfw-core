/* Static cross-language guard: the opcode and register numbers in src/isa.js
 * must match the C enums in bpf/include/pfw.h exactly — a silent mismatch makes
 * the kernel read every op as the wrong one, and no behavioral (JS-only) test
 * catches it because both the assembler and the interpreter use isa.js. Runs
 * under node (it reads the C header, which the yeet sandbox cannot); the rest of
 * the suite is `yeet test`. */
import { readFileSync } from "node:fs";
import { DECIDE_BOUNDS, HOST_LIMITS, LIMITS, OP, REG } from "#/isa.js";

const h = readFileSync(new URL("../../bpf/include/pfw.h", import.meta.url), "utf8");
const parseEnum = (nm) => {
  const body = h.match(new RegExp("enum " + nm + "\\s*\\{([\\s\\S]*?)\\}", "m"))[1];
  let val = 0;
  const out = {};
  for (let ln of body.split("\n")) {
    ln = ln.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*/, "");
    for (const tok of ln.split(",")) {
      const a = tok.trim().match(/^([A-Z_][A-Z0-9_]*)\s*(=\s*(\d+))?$/);
      if (!a) continue;
      if (a[3] !== undefined) val = Number(a[3]);
      out[a[1]] = val++;
    }
  }
  return out;
};

const cOps = parseEnum("pfw_opcode"), cRegs = parseEnum("pfw_reg");
const ralias = { saddr: "R_SADDR", src: "R_SADDR" };
let bad = 0;
for (const [k, v] of Object.entries(OP)) if (cOps["OP_" + k] !== v) { bad++; console.log(`opcode ${k}: isa=${v} pfw.h=${cOps["OP_" + k]}`); }
for (const [k, v] of Object.entries(REG)) { const hn = ralias[k] ?? "R_" + k.toUpperCase(); if (cRegs[hn] !== v) { bad++; console.log(`reg ${k}: isa=${v} pfw.h=${cRegs[hn]}`); } }

/* The histogram's bucket bounds are an X-macro in the header and a list on the
 * host; a host that disagrees mislabels every bucket. */
const cBounds = [...h.match(/#define DECIDE_BOUNDS\(X\)([\s\S]*?)\n\n/)[1].matchAll(/X\((\d+)\)/g)].map((m) => Number(m[1]));
if (JSON.stringify(cBounds) !== JSON.stringify(DECIDE_BOUNDS)) { bad++; console.log(`DECIDE_BOUNDS: isa=${DECIDE_BOUNDS} pfw.h=${cBounds}`); }

/* The budgets. A limit raised on one side only is the dangerous kind of
 * mismatch: the compiler accepts a program the kernel masks into a different
 * one. A LIMITS key is spelled in the header as itself, or with the PFW_ prefix
 * or the _MAX / _CAP suffix the header uses. */
const define = (nm) => { const m = h.match(new RegExp("^#define " + nm + "\\s+(\\d+)\\b", "m")); return m ? Number(m[1]) : undefined; };
let nlimits = 0;
for (const [k, v] of Object.entries(LIMITS)) {
  if (HOST_LIMITS.includes(k)) continue;
  const c = [k, "PFW_" + k, k + "_MAX", k + "_CAP"].map(define).find((x) => x !== undefined);
  if (c !== v) { bad++; console.log(`limit ${k}: isa=${v} pfw.h=${c}`); }
  nlimits++;
}

console.log(bad ? `${bad} mismatch(es) between isa.js and pfw.h` : `isa.js <-> pfw.h: ${Object.keys(OP).length} opcodes, ${Object.keys(REG).length} registers, ${nlimits} limits agree`);
process.exit(bad ? 1 : 0);
