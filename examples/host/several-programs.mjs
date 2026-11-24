/* Several programs on one interface: a default, a program of its own for one
 * port and for one destination prefix, and a stage every packet runs first.
 *
 *   yeet run examples/host/several-programs.mjs [--iface 1] [--hold 30]
 *
 * It attaches to the interface (loopback by default), installs four programs,
 * prints which program each verdict came from, and after `--hold` seconds
 * prints what each one counted and detaches. Try it against loopback:
 *
 *   curl -A sqlmap http://127.0.0.1:8080/          # the default: reset
 *   curl http://127.0.0.1:8443/admin               # tcp/8443's own program: reset
 *   curl 'http://127.0.0.2:8080/..%2fetc/passwd'   # the 127.0.0.2/32 program: reset
 *
 * The kernel allows one XDP program on an interface. The VM is that program,
 * and the programs here are data it dispatches each packet to.
 */
import { PfwVm } from "#/loader.js";
import { load } from "#/index.js";

const argv = yeet.args ?? {};
const iface = Number(argv.iface ?? 1), hold = Number(argv.hold ?? 30);

/* Every packet runs this first, whatever program it is headed for. It keeps
 * its own count for each source, and bans one that sends too much; everything
 * else it passes on. A stage cannot `reassemble`: it sees packets as they come. */
const FLOOD_GUARD = load(`filter {
  if (proto != 6) decide pass;
  if (src.rate(2000, 4000)) decide ban("flood", 30);
  decide pass;
}`);

/* The default: for every packet no route claims. */
const DEFAULT = load(`nocase;
pattern sqlmap = "sqlmap", nikto = "nikto";
filter {
  if (proto != 6) decide pass;
  if (any(scan(payload, 1024), sqlmap, nikto)) { log(64); decide rst("scanner", 0); }
  decide pass;
}`);

/* TCP port 8443 has a program of its own: it follows the stream, so a request
 * line split across segments is still seen whole. The request line is a regex
 * that says its own case, so it matches a request and not a mention of one. */
const API = load(String.raw`reassemble 8443;
regex admin = "(?-i)(GET|POST) /admin[^ \r\n]* HTTP/1\.[01]";
filter {
  if (scan(payload, 4096) & admin) { log(64); decide rst("admin_from_outside", 0); }
  decide pass;
}`);

/* And so does one destination address, whatever the port. A route with a
 * longer prefix wins over a shorter one, and over one with none. */
const TENANT = load(`pattern dotdot = "../", enc = "..%2f";
filter {
  if (proto != 6) decide pass;
  if (any(scan(payload, 1024), dotdot, enc)) { log(64); decide rst("traversal", 0); }
  decide pass;
}`);

const vm = new PfwVm({ iface });
vm.onVerdict((e) => console.log(`${e.verdict} (${e.route}: ${e.rule}) ${e.src} -> ${e.dst}:${e.dport}`));

await vm.start();
await vm.apply(DEFAULT);
await vm.route({ proto: "tcp", dport: 8443 }, API);
await vm.route({ dst: "127.0.0.2" }, TENANT);
await vm.first(FLOOD_GUARD);
console.log(`attached to interface ${iface}: default, ${Object.keys(vm.routes).join(", ")}, and one stage`);

await new Promise((r) => setTimeout(r, hold * 1000));

/* A rule's count is the times it decided; `enforced_rules` is the packets its
 * standing mark or ban went on to stop. */
const J = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? Number(v) : v));
const s = await vm.stats();
console.log(`default: ${J(s.rules)}`);
for (const [name, r] of Object.entries(s.routes)) console.log(`${name}: ${J(r.rules)}`);
for (const f of s.first) console.log(`${f.name}: ${J(f.rules)}, stopped since: ${J(f.enforced_rules)}`);

await vm.stop();
console.log("detached");
