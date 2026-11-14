/* console("fmt", args...) — printf-style messages to the host. Numeric args
 * (%d %u %x %c ...) are captured by value; %s captures bytes from a packet
 * pointer. The reference interpreter formats them (same formatter the loader
 * uses) and exec() returns them in `console`, and calls opts.onConsole if given. */
import { compile } from "#/clang.js";
import { toProgram } from "#/program.js";
import { formatMsg } from "#/program.js";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("numeric console formats like printf", () => {
  const p = prog(`filter { console("port=%d proto=%d hex=%x", dport, proto, dport); return pass; }`);
  const r = p.exec(enc("x"), { dport: 443, proto: 6 });
  eq(r.verdict, "pass", "verdict");
  eq(r.console[0], "port=443 proto=6 hex=1bb", "formatted");
});

yeet.test("%s captures a string from a packet pointer", () => {
  const p = prog(`filter { console("req=%s", payload); return pass; }`);
  const r = p.exec(enc("GET /index"), { payload: 0 });
  eq(r.console[0], "req=GET /index", "string arg from payload");
});

yeet.test("%s is capped at 256 bytes", () => {
  const p = prog(`filter { console("b=%s", payload); return pass; }`);
  const r = p.exec(enc("A".repeat(400)), { payload: 0 });
  eq(r.console[0], "b=" + "A".repeat(256), "truncated to the cap");
});

yeet.test("mixed numeric and string args interleave in format order", () => {
  const p = prog(`filter { console("%s:%d", payload, dport); return pass; }`);
  const r = p.exec(enc("host"), { payload: 0, dport: 8080 });
  eq(r.console[0], "host:8080", "interleaved");
});

yeet.test("onConsole callback fires per message", () => {
  const p = prog(`filter { console("a=%d", dport); console("b=%d", proto); return pass; }`);
  const seen = [];
  p.exec(enc("x"), { dport: 1, proto: 2, onConsole: (line) => seen.push(line) });
  eq(seen.join("|"), "a=1|b=2", "both messages via callback");
});

yeet.test("the compiler checks arg count against the format", () => {
  const r = compile(`filter { console("%d %d", dport); return pass; }`);
  if (r.ok) throw new Error("expected an arg-count error");
  if (!JSON.stringify(r.errors).includes("conversion")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});

yeet.test("formatMsg handles %% and %c", () => {
  eq(formatMsg("100%% done, ch=%c", [65]), "100% done, ch=A", "literal percent + char");
});
