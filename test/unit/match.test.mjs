/* match / switch / break. `match` runs exactly one arm (no fall-through), with
 * block-delimited `case V [, V] { ... }` and optional `default { ... }`. `switch`
 * is C-style: `case V:` statement lists that fall through until `break;`. Both
 * evaluate the scrutinee once; no new opcodes (compare + forward jumps). */
import { compile } from "#/clang";
import { toProgram } from "#/program";

const enc = (s) => new TextEncoder().encode(s);
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
const prog = (src) => { const c = compile(src); if (!c.ok) throw new Error("compile: " + JSON.stringify(c.errors)); return toProgram(c); };

yeet.test("match runs exactly one arm (no fall-through)", () => {
  const p = prog(`filter { match (dport) { case 22 { decide drop("ssh"); } case 80, 443 { decide rst("web", 0); } default { decide pass; } } }`);
  eq(p.exec(enc("x"), { dport: 22 }).verdict, "drop", "22");
  eq(p.exec(enc("x"), { dport: 80 }).verdict, "rst", "80 (shared arm)");
  eq(p.exec(enc("x"), { dport: 443 }).verdict, "rst", "443 (shared arm)");
  eq(p.exec(enc("x"), { dport: 8080 }).verdict, "pass", "default");
});

yeet.test("match without a matching arm and no default falls through to the rest", () => {
  const p = prog(`filter { match (dport) { case 1 { decide drop("x"); } } decide pass; }`);
  eq(p.exec(enc("x"), { dport: 9 }).verdict, "pass", "no arm, no default");
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "drop", "arm 1");
});

yeet.test("switch falls through until break", () => {
  // case 1 has no break -> falls into case 2
  const p = prog(`filter { switch (dport) { case 1: count("a"); case 2: decide drop("one_or_two"); default: decide pass; } }`);
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "drop", "1 falls into 2");
  eq(p.exec(enc("x"), { dport: 2 }).verdict, "drop", "2");
  eq(p.exec(enc("x"), { dport: 9 }).verdict, "pass", "default");
});

yeet.test("break exits the switch", () => {
  const p = prog(`filter { switch (dport) { case 1: decide rst("one", 0); case 2: count("two"); break; default: decide drop("d"); } decide pass; }`);
  eq(p.exec(enc("x"), { dport: 2 }).verdict, "pass", "2: counts then break -> pass");
  eq(p.exec(enc("x"), { dport: 9 }).verdict, "drop", "default");
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "rst", "1");
});

yeet.test("match works on flow.state and on a subroutine param", () => {
  const p = prog(`fn classify(s) { match (s) { case 0 { return 10; } case 1 { return 20; } default { return 0; } } }
                  filter { if (classify(dport) == 20) decide drop("one"); decide pass; }`);
  eq(p.exec(enc("x"), { dport: 1 }).verdict, "drop", "param match -> 20");
  eq(p.exec(enc("x"), { dport: 5 }).verdict, "pass", "default -> 0");
});

yeet.test("break outside a switch/match is a compile error", () => {
  const r = compile(`filter { break; decide pass; }`);
  if (r.ok) throw new Error("expected a break-outside error");
  if (!JSON.stringify(r.errors).includes("break")) throw new Error("wrong error: " + JSON.stringify(r.errors));
});

/* within(ptr, n): the fresh scan. scan() ORs into the one match mask, so a second
 * scan over a narrower window still reports what the first one saw anywhere;
 * within() starts from an empty mask and automaton, so its result is exactly the
 * patterns inside its window. */
yeet.test("scan accumulates across scans; within reports only its own window", async () => {
  const { load } = await import("#/index.js");
  const req = new TextEncoder().encode("GET /blog/gptbot-news HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n");
  const bot = new TextEncoder().encode("GET /index.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; GPTBot/1.2)\r\nAccept: */*\r\n\r\n");
  const prog = (fn) => load(`nocase; pattern ua = "user-agent: ", gptbot = "gptbot";
    filter { if (!(scan(payload, 1024) & ua)) decide pass; ptr agent = after(ua); if (${fn}(agent, 128) & gptbot) decide drop("bot"); decide pass; }`);
  const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };
  eq(prog("scan").exec(req, {}).verdict, "drop", "scan: the bot name in the PATH leaks into the 'anchored' test");
  eq(prog("within").exec(req, {}).verdict, "pass", "within: a bot name in the path is not in the user-agent");
  eq(prog("within").exec(bot, {}).verdict, "drop", "within: a bot name in the user-agent is caught");
});

yeet.test("within does not complete a match begun before its window", async () => {
  const { load } = await import("#/index.js");
  /* "EVIL" ends exactly where the window starts: the tail "PAYLOAD" alone is not the pattern. */
  const p = load(`pattern sig = "EVILPAYLOAD", mark = "|"; filter { if (!(scan(payload, 4) & mark)) decide pass; ptr q = after(mark); if (within(q, 64) & sig) decide drop("sig"); decide pass; }`);
  const r = p.exec(new TextEncoder().encode("EVI|PAYLOAD..."), {});
  if (r.verdict !== "pass") throw new Error("a fresh scan must restart the automaton: got " + r.verdict);
});
