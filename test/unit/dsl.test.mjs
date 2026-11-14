/* The JS program builder (dsl.js) must produce exactly what the equivalent
 * pfw-C source compiles to — same ops, patterns, rules and flags. Each case pairs
 * a source string with the DSL that should match it; a mismatch means the builder
 * and the language have drifted. Also covers the Program wrapper the DSL returns. */
import { compile } from "#/clang";
import * as C from "#/dsl.js";
import { Program } from "#/program";

const J = (x) => JSON.stringify(x, (_, val) => (typeof val === "bigint" ? "0x" + val.toString(16) : val));
const sameProgram = (name, source, prog) => {
  const c = compile(source);
  if (!c.ok) throw new Error(`${name}: source failed to compile: ${J(c.errors)}`);
  const a = { ops: c.program.ops, decode: c.program.decode, tt: c.program.transform_table, reasm: c.program.reasm, dport: c.program.reasm_dport, nocase: c.program.nocase, pats: c.program.pats, rules: c.rules.map((r) => r.name) };
  const b = { ops: prog.program.ops, decode: prog.program.decode, tt: prog.program.transform_table, reasm: prog.program.reasm, dport: prog.program.reasm_dport, nocase: prog.program.nocase, pats: prog.program.pats, rules: prog.rules.map((r) => r.name) };
  if (J(a) !== J(b)) throw new Error(`${name}: DSL != source\n source: ${J(a)}\n dsl:    ${J(b)}`);
};

yeet.test("crawler rule (nocase, patterns, scan, any, rst)", () => {
  sameProgram("crawler",
    `nocase;
     pattern gptbot = "GPTBot", claudebot = "ClaudeBot";
     filter {
       if (dport != 80) decide pass;
       if (scan(payload, 1460) & (gptbot | claudebot)) decide rst("crawler", 60);
       decide pass;
     }`,
    C.program(
      C.nocase(),
      C.pattern("gptbot", "GPTBot"),
      C.pattern("claudebot", "ClaudeBot"),
      C.filter(
        C.iff(C.ne(C.dport, 80), C.pass()),
        C.iff(C.band(C.scan(C.payload, 1460), "gptbot", "claudebot"), C.rst("crawler", 60)),
        C.pass(),
      ),
    ));
});

yeet.test("cidr allow/deny", () => {
  sameProgram("cidr",
    `filter {
       if (proto != 6) decide pass;
       if (src in "10.0.0.0/8") decide pass;
       if (src in "203.0.113.0/24") decide drop("blocklist");
       decide pass;
     }`,
    C.program(C.filter(
      C.iff(C.ne(C.proto, 6), C.pass()),
      C.iff(C.inCidr(C.src, "10.0.0.0/8"), C.pass()),
      C.iff(C.inCidr(C.src, "203.0.113.0/24"), C.drop("blocklist")),
      C.pass(),
    )));
});

yeet.test("if/else, and, let arithmetic", () => {
  sameProgram("mix",
    `filter {
       let n = len + 2;
       if (dport == 80 && n > 10) { decide drop("big"); } else { decide pass; }
     }`,
    C.program(C.filter(
      C.let_("n", C.add(C.len, 2)),
      C.iff(C.and(C.eq(C.dport, 80), C.gt("n", 10)), C.drop("big"), C.pass()),
    )));
});

yeet.test("ring over a reassembled flow", () => {
  sameProgram("ring",
    `reassemble 8080;
     filter {
       if (len == 0) decide pass;
       ring.push(len);
       if (ring.len >= 8) decide rst("too_many", 0);
       decide pass;
     }`,
    C.program(C.reassemble(8080), C.filter(
      C.iff(C.eq(C.len, 0), C.pass()),
      C.ringPush(C.len),
      C.iff(C.ge(C.ringLen, 8), C.rst("too_many", 0)),
      C.pass(),
    )));
});

yeet.test("frame walk with type gating", () => {
  sameProgram("frame",
    `pattern bot = "GPTBot";
     filter {
       if (proto != 6) decide pass;
       frame (len = be24 @ 0, type = u8 @ 3, head = 9) up to 8 {
         if (frame.type == 1) {
           if (scan(frame.data, 1024) & bot) decide rst("h2_bot", 0);
         }
       }
       decide pass;
     }`,
    C.program(C.pattern("bot", "GPTBot"), C.filter(
      C.iff(C.ne(C.proto, 6), C.pass()),
      C.frameWalk({ len: { type: "be24", off: 0 }, type: { type: "u8", off: 3 }, head: 9, up: 8 },
        C.iff(C.eq(C.frameType, 1),
          C.iff(C.band(C.scan(C.frameData, 1024), "bot"), C.rst("h2_bot", 0)))),
      C.pass(),
    )));
});

yeet.test("decode directives set the right program fields", () => {
  sameProgram("huffman",
    `decode huffman 8080; pattern bot = "GPTBot"; filter { if (scan(payload,2048) & bot) decide rst("x",0); decide pass; }`,
    C.program(C.decode("huffman", 8080), C.pattern("bot", "GPTBot"),
      C.filter(C.iff(C.band(C.scan(C.payload, 2048), "bot"), C.rst("x", 0)), C.pass())));
  sameProgram("transform",
    `decode unshift1 8080; pattern bot = "GPTBot"; filter { if (scan(payload,2048) & bot) decide rst("x",0); decide pass; }`,
    C.program(C.decode("unshift1", 8080), C.pattern("bot", "GPTBot"),
      C.filter(C.iff(C.band(C.scan(C.payload, 2048), "bot"), C.rst("x", 0)), C.pass())));
});

yeet.test("the DSL returns a runnable Program", () => {
  const p = C.program(C.filter(C.pass()));
  if (!(p instanceof Program)) throw new Error("program() should return a Program");
  if (typeof p.exec !== "function" || typeof p.bytes !== "function") throw new Error("missing runtime methods");
});
