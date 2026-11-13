/* Static cross-language guard: the opcode and register numbers in src/isa.js
 * must match the C enums in bpf/include/pfw.h exactly — a silent mismatch makes
 * the kernel read every op as the wrong one, and no behavioral (JS-only) test
 * catches it because both the assembler and the interpreter use isa.js. Runs
 * under node (it reads the C header, which the yeet sandbox cannot); the rest of
 * the suite is `yeet test`. */
import { readFileSync } from "node:fs";
import { OP, REG } from "#/isa.js";

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

console.log(bad ? `${bad} mismatch(es) between isa.js and pfw.h` : `isa.js <-> pfw.h: ${Object.keys(OP).length} opcodes, ${Object.keys(REG).length} registers agree`);
process.exit(bad ? 1 : 0);
