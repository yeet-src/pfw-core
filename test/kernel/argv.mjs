/* Kernel argv test: prove a program's behaviour is steered by runtime args the
 * host sets at load time — the SAME compiled bytecode, no recompile. The program
 * resets connections to whatever port argv[0] names (default 1):
 *
 *   filter { if (dport != argv[0] ?? 1) return pass;
 *            log(16); return rst("port_arg", 0); }
 *
 *   - loaded with no args  -> argv[0] defaults to 1, so :PORT passes (no event)
 *   - loaded with --argv PORT -> argv[0] = PORT, so :PORT is reset (RST event)
 *
 * The verdict is read from the events ring (log(16) arms the event). Needs
 * yeetd + loopback; `npm run test:argv` (node). */
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { V } from "#/interp.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const PORT = 59661;
const hex = (s) => Buffer.from(s, "utf8").toString("hex");

async function withProgram(source, argv, fn) {
  const args = ["run", "scripts/apply-and-hold.mjs", "--src", hex(source), "--iface", "1", "--hold", "25"];
  if (argv) args.push("--argv", argv);
  const child = spawn("yeet", args, { cwd: ROOT });
  const events = [];
  let out = "";
  child.stdout.on("data", (d) => { out += d; for (const m of String(d).matchAll(/EVENT (\d+)/g)) events.push(Number(m[1])); });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 120 && !/READY/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error("loader never READY:\n" + out); }
  try { return await fn(events); } finally { child.kill("SIGINT"); await sleep(400); }
}

function connect() {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: PORT });
    const done = () => { try { sock.destroy(); } catch {} resolve(); };
    sock.setTimeout(1200, done);
    sock.on("connect", () => { sock.write("x"); setTimeout(done, 300); });
    sock.on("data", done); sock.on("error", done);
  });
}

const source = `filter { if (dport != argv[0] ?? 1) return pass; log(16); return rst("port_arg", 0); }`;
const CASES = [
  { name: "no args: argv[0] defaults to 1, :PORT passes", argv: null, want: V.PASS },
  { name: `--argv ${PORT}: argv[0] steers the reset to :PORT`, argv: String(PORT), want: V.RST },
];

const vname = (v) => ({ [V.PASS]: "pass", [V.RST]: "rst" }[v] ?? v);
let fail = 0, n = 0;
const server = net.createServer((s) => { s.on("data", () => s.write("ok")); s.on("error", () => {}); });
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
console.log(`kernel argv — runtime args steer the same bytecode on :${PORT}\n`);
try {
  for (const c of CASES) {
    await withProgram(source, c.argv, async (events) => {
      await sleep(600);
      const before = events.length;
      await connect();
      await sleep(600);
      const obs = events.slice(before).includes(V.RST) ? V.RST : V.PASS;
      n++;
      const ok = obs === c.want;
      if (!ok) fail++;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${c.name}: kernel=${vname(obs)}`);
    });
  }
} finally { server.close(); }
console.log(`\n${n - fail}/${n} as expected`);
process.exit(fail ? 1 : 0);
