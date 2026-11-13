/* `frame` (P4): compile a frame-walking rule and run it over synthetic
 * length-prefixed records. The point is structure-awareness, so the key case is
 * that the same "GPTBot" bytes trigger only inside a record of the targeted type
 * and never bleed across a record edge. */
import { compile } from "#/clang.js";
import { assemble } from "#/asm.js";
import { build } from "#/ac.js";
import { machine, V } from "#/interp.js";

const enc = new TextEncoder();
/* h2-style frame: 9-byte header (len be24 @0, type u8 @3), then the payload. */
function frameBytes(type, payload) {
  const p = enc.encode(payload);
  const out = new Uint8Array(9 + p.length);
  out[0] = (p.length >> 16) & 0xff; out[1] = (p.length >> 8) & 0xff; out[2] = p.length & 0xff; out[3] = type;
  out.set(p, 9);
  return out;
}
const cat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const SET = (s) => frameBytes(4, s);  // SETTINGS
const HDR = (s) => frameBytes(1, s);  // HEADERS

const c = compile(`
pattern bot = "GPTBot";
filter {
  if (proto != 6) return pass;
  frame (len = be24 @ 0, type = u8 @ 3, head = 9) up to 4 {
    if (frame.type == 1) {
      if (scan(frame.data, 256) & bot) return rst("bot", 0);
    }
  }
  return pass;
}`);
if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
const asm = assemble(c.asm);
if (!asm.ok) throw new Error("assemble: " + JSON.stringify(asm.errors));
const run = machine({ asm, tables: build(asm.patterns, asm.nocase) });
const verdict = (buf) => run(buf, 0, { ac: 0, mask: 0n }, { proto: 6 }).verdict === V.RST ? "rst" : "pass";
const want = (name, buf, exp) => { const got = verdict(buf); if (got !== exp) throw new Error(`${name}: ${got} (want ${exp})`); };

yeet.test("GPTBot in a HEADERS frame resets", () => want("headers", cat(SET("hello"), HDR("ua=GPTBot/1")), "rst"));
yeet.test("GPTBot only in a SETTINGS frame passes", () => want("settings", cat(HDR("nothing here"), SET("ua=GPTBot/1")), "pass"));
yeet.test("no bot passes", () => want("clean", cat(SET("hello"), HDR("ua=Chrome")), "pass"));
yeet.test("walk reaches the 3rd record", () => want("third", cat(SET("a"), SET("bb"), HDR("x GPTBot x")), "rst"));
yeet.test("truncated trailing header does not crash", () => want("trunc", cat(SET("ok"), Uint8Array.of(0, 0, 9, 1)), "pass"));
