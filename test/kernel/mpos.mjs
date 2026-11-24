/* Kernel mpos test: `after(pat)` for a pattern id above 31. The op's reg field
 * carries a 6-bit pattern id, not a 5-bit register index — masking it as a
 * register made pattern 33 read pattern 1's position. The payload holds pattern
 * 1 early and pattern 33 later; the program resets only when after(p33) is the
 * later offset. Needs yeetd + loopback; `npm run test:mpos`. */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { load } from "#/index.js";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59723;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

const tag = (i) => `<${String.fromCharCode(65 + (i >> 4), 97 + (i & 15))}>`;
const PAYLOAD = `..${tag(1)}....${tag(33)}`; // p1 ends at 6, p33 ends at 14
const source = (want) => `${Array.from({ length: 34 }, (_, i) => `pattern p${i} = "${tag(i)}";`).join("\n")}
filter {
  if (dport != ${PORT}) decide pass;
  mask m = scan(payload, 64);
  if (any(m, p33)) { let d = after(p33) - payload; if (d == ${want}) { log(16); decide rst("mpos", 0); } }
  decide pass;
}`;

async function withProgram(src, fn) {
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(src), "--iface", "1", "--hold", "25"], { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 900 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function send() {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write(PAYLOAD); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const CASES = [
  ["after(p33) is p33's own position (14)", 14, V.RST],
  ["after(p33) is not p1's position (6)", 6, V.PASS],
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel mpos — pattern ids above 31 on :${PORT}\n`);
try {
  for (const [name, want, expect] of CASES) {
    const ref = load(source(want)).exec(Buffer.from(PAYLOAD), { dport: PORT }).verdict;
    await withProgram(source(want), async (events) => {
      await sleep(500);
      const before = events.length;
      await send();
      await sleep(500);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++; const ok = obs === expect && ref === vname(expect); if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${name}: reference=${ref} kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
