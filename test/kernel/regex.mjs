/* Kernel regex test: load a program with a `regex` pattern, send loopback
 * traffic, and read the verdict from the loader's event stream — RST when the
 * payload matches the regex (via the DFA the loader populated into re_goto/
 * re_accept), PASS when it doesn't. Proves fuzzy matching works in the kernel.
 * Needs yeetd + loopback; `npm run test:regex` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59611;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function send(payload) {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, "127.0.0.1");
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write(Buffer.from(payload)); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

// Reset on an SSN, an email, or a 13-16 digit card; else pass.
const source = `nocase;
regex ssn = "\\d{3}-\\d{2}-\\d{4}";
regex email = "[a-z0-9._]+@[a-z0-9.]+\\.[a-z]+";
regex card = "\\d{13,16}";
filter { if (dport != ${PORT}) decide pass; if (any(scan(payload, 512), ssn, email, card)) { log(16); decide rst("pii", 0); } decide pass; }`;

// The same three, an AWS access key id and a JWT, in one program. As one DFA
// they pass 65536 states; the compiler splits them across three, some 2600
// states in all, and the kernel walks the three side by side.
const bigSource = `nocase;
regex ssn = "\\d{3}-\\d{2}-\\d{4}";
regex email = "[a-z0-9._]+@[a-z0-9.]+\\.[a-z]+";
regex card = "\\d{13,16}";
regex aws = "AKIA[A-Z0-9]{16}";
regex jwt = "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}";
filter { if (dport != ${PORT}) decide pass; if (any(scan(payload, 512), ssn, email, card, aws, jwt)) { log(16); decide rst("pii", 0); } decide pass; }`;

const CASES = [
  ["SSN -> rst", "my ssn is 123-45-6789 ok", V.RST],
  ["email -> rst", "reach me at bob@example.com", V.RST],
  ["card -> rst", "pan 4111111111111111 exp", V.RST],
  ["clean -> pass", "just a normal request body", V.PASS],
  ["near-miss SSN -> pass", "code 12-345-6789 here", V.PASS],
];
// One rule of a case-insensitive program that says its own case: a request
// line, matched as a request line. A prompt that mentions the same words in
// lower case is not one.
const exactSource = `nocase;
pattern agent = "gptbot";
regex probe = "(?-i)POST /guardrails/test_custom_code[^ \\r\\n]* HTTP/1\\.[01]";
filter { if (dport != ${PORT}) decide pass; mask m = scan(payload, 512); if (m & probe) { log(16); decide rst("probe", 0); } if (m & agent) { log(16); decide rst("agent", 0); } decide pass; }`;
const EXACT_CASES = [
  ["the request line itself -> rst", "POST /guardrails/test_custom_code HTTP/1.1\r\nHost: x\r\n\r\n", V.RST],
  ["lower-case prose that mentions it -> pass", "POST /chat HTTP/1.1\r\n\r\nhow do i post /guardrails/test_custom_code http/1.1 safely", V.PASS],
  ["the program's own case still ignores case -> rst", "GET / HTTP/1.1\r\nUser-Agent: GPTBot\r\n\r\n", V.RST],
];
const BIG_CASES = [
  ["aws key -> rst", "key AKIAIOSFODNN7EXAMPLE end", V.RST],
  ["aws key one byte short -> pass", "key AKIAIOSFODNN7EXAMPL end", V.PASS],
  ["...and an SSN beside it -> rst", "my ssn is 123-45-6789 ok", V.RST],
  ["...and a JWT -> rst", "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 x", V.RST],
  ["...and half a JWT -> pass", "auth eyJhbGciOiJIUzI1NiJ9 x", V.PASS],
  ["...and clean text -> pass", "just a normal request body", V.PASS],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst", [V.DROP]: "drop" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel regex — fuzzy matching (DFA) on :${PORT}\n`);
try {
  for (const [src, cases] of [[source, CASES], [bigSource, BIG_CASES], [exactSource, EXACT_CASES]]) await withProgram(src, async (events) => {
    for (const [name, payload, want] of cases) {
      await sleep(700);
      const before = events.length;
      await send(payload);
      await sleep(700);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++;
      const ok = obs === want;
      if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: kernel=${vname(obs)}`);
    }
  });
} finally { server.close(); }
console.log(`\n${n - fail}/${n} agree`);
process.exit(fail ? 1 : 0);
