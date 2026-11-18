/* sample(len [, "tag"]) — a copy of the frame for the host: a capture of what a
 * rule matched, a feed for an IDS. The packet itself goes wherever the verdict
 * sends it. */
import { load } from "#/index.js";
import { compile } from "#/clang";
import { LIMITS } from "#/isa.js";

const eq = (g, w, m) => { if (JSON.stringify(g) !== JSON.stringify(w)) throw new Error(`${m}: got ${JSON.stringify(g)}, want ${JSON.stringify(w)}`); };
const bytes = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
const text = (u8) => String.fromCharCode(...u8);
const view = (samples) => samples.map((s) => [s.tag, text(s.data), s.wireLen]);

yeet.test("a sample is the frame's first bytes, whatever the verdict", () => {
  const p = load(`pattern bad = "attack"; filter { if (scan(payload, 64) & bad) { sample(12, "matched"); decide drop("ids"); } decide pass; }`);
  const hit = p.exec(bytes("an attack in a packet"), {});
  eq(hit.verdict, "drop", "the packet is dropped");
  eq(view(hit.samples), [["matched", "an attack in", 21]], "and the host has its first 12 bytes, and its real length");
  eq(p.exec(bytes("nothing to see"), {}).samples, [], "no match, no sample");
});

yeet.test("the whole frame, when it is shorter than the length asked for", () => {
  const p = load(`filter { sample(${LIMITS.SAMPLE_CAP}); decide pass; }`);
  const r = p.exec(bytes("short"), {});
  eq(view(r.samples), [[null, "short", 5]], "untagged, complete");
  eq(r.verdict, "pass", "sampling is not a verdict");
});

yeet.test("tags name what was sampled; the program lists them", () => {
  const p = load(`filter { if (dport == 22) sample(8, "ssh"); if (dport == 23) sample(8, "telnet"); if (len > 4) sample(4); decide pass; }`);
  eq(p.sampleTags, ["", "ssh", "telnet"], "tag names by id");
  eq(view(p.exec(bytes("123456789"), { dport: 23 }).samples), [["telnet", "12345678", 9], [null, "1234", 9]], "two samples of one packet");
});

yeet.test("one in N: sampling by the flow hash", () => {
  // Every packet of a connection is kept or none is, so a capture has whole flows.
  const p = load(`filter { if (flow.hash % 16 == 0) sample(64, "one_in_16"); decide pass; }`);
  let kept = 0;
  for (let sport = 40000; sport < 40800; sport++) kept += p.exec(bytes("x"), { src: "10.0.0.1", dst: "10.0.0.2", sport, dport: 443 }).samples.length;
  if (kept < 25 || kept > 80) throw new Error(`kept ${kept} of 800: expected about 50`);
});

yeet.test("the callback form, as the loader delivers them", () => {
  const got = [];
  load(`filter { sample(3, "a"); decide pass; }`).exec(bytes("abcdef"), { onSample: (s) => got.push([s.tag, text(s.data)]) });
  eq(got, [["a", "abc"]], "onSample");
});

yeet.test("the length is a constant within the cap, the tag a name", () => {
  eq(compile(`filter { sample(0); decide pass; }`).ok, false, "a length of 0");
  eq(compile(`filter { sample(${LIMITS.SAMPLE_CAP + 1}); decide pass; }`).ok, false, "past the cap");
  eq(compile(`filter { sample(len); decide pass; }`).ok, false, "a computed length");
  eq(compile(`filter { sample(8, dport); decide pass; }`).ok, false, "a tag that is not a string");
  eq(compile(`filter { sample(); decide pass; }`).ok, false, "no length");
});
