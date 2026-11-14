/* dnat(ip, port) — rewrites the packet's destination and forwards. It rewrites
 * packet headers, which the host frame model (payload-only) has not got, so it is
 * kernel-only: here we check it compiles (pfw-C + DSL, with IP/port validation)
 * and is a pass-through in the reference interpreter. The wire behaviour is in
 * test/kernel/dnat.mjs. */
import * as C from "#/dsl.js";
import { compile } from "#/clang";

const enc = (s) => new TextEncoder().encode(s);
const J = (ops) => JSON.stringify(ops, (_, v) => (typeof v === "bigint" ? "0x" + v.toString(16) : v));

yeet.test("dnat compiles and is a pass-through in the host model", () => {
  const c = compile(`filter { if (proto != 17) decide pass; if (dport != 5000) decide pass; dnat("10.0.0.5", 8080); decide pass; }`);
  if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors));
  const p = C.program(C.filter(
    C.iff(C.ne(C.proto, 17), C.pass()),
    C.iff(C.ne(C.dport, 5000), C.pass()),
    C.dnat("10.0.0.5", 8080), C.pass()));
  if (p.exec(enc("x"), { proto: 17, dport: 5000 }).verdict !== "pass") throw new Error("dnat should pass in host model");
});

yeet.test("dnat rejects a bad IPv4 or port at compile time", () => {
  if (compile(`filter { dnat("999.0.0.1", 80); decide pass; }`).ok) throw new Error("bad ip accepted");
  if (compile(`filter { dnat("10.0.0.1", 99999); decide pass; }`).ok) throw new Error("bad port accepted");
  if (compile(`filter { dnat("nope", 80); decide pass; }`).ok) throw new Error("non-ip accepted");
});

yeet.test("dnat: DSL compiles identically to source", () => {
  const s = compile(`filter { dnat("10.0.0.5", 8080); decide pass; }`);
  if (!s.ok) throw new Error("source: " + JSON.stringify(s.errors));
  const d = C.program(C.filter(C.dnat("10.0.0.5", 8080), C.pass()));
  if (J(s.program.ops) !== J(d.program.ops)) throw new Error("DSL != source");
});
