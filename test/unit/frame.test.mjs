/* `frame` (P4): compile a frame-walking rule and run it over synthetic
 * length-prefixed records. The point is structure-awareness, so the key case is
 * that the same "GPTBot" bytes trigger only inside a record of the targeted type
 * and never bleed across a record edge. */
import { fromC, V, enc } from "./helpers.mjs";

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

const { run } = fromC(`
pattern bot = "GPTBot";
filter {
  if (proto != 6) decide pass;
  frame (len = be24 @ 0, type = u8 @ 3, head = 9) up to 4 {
    if (frame.type == 1) {
      if (scan(frame.data, 256) & bot) decide rst("bot", 0);
    }
  }
  decide pass;
}`);
const verdict = (buf) => run(buf, {}, { proto: 6 }).verdict === V.RST ? "rst" : "pass";
const want = (name, buf, exp) => { const got = verdict(buf); if (got !== exp) throw new Error(`${name}: ${got} (want ${exp})`); };

yeet.test("GPTBot in a HEADERS frame resets", () => want("headers", cat(SET("hello"), HDR("ua=GPTBot/1")), "rst"));
yeet.test("GPTBot only in a SETTINGS frame passes", () => want("settings", cat(HDR("nothing here"), SET("ua=GPTBot/1")), "pass"));
yeet.test("no bot passes", () => want("clean", cat(SET("hello"), HDR("ua=Chrome")), "pass"));
yeet.test("walk reaches the 3rd record", () => want("third", cat(SET("a"), SET("bb"), HDR("x GPTBot x")), "rst"));
yeet.test("truncated trailing header does not crash", () => want("trunc", cat(SET("ok"), Uint8Array.of(0, 0, 9, 1)), "pass"));

/* ---- varint lengths and adjusted lengths ---- */
{
  const { compile } = await import("#/clang");
  const bytes = (...parts) => Uint8Array.from(parts.flat());
  const text = (s) => Array.from(s, (ch) => ch.charCodeAt(0));
  const v = (src, buf) => fromC(src).run(buf, {}, { proto: 6 }).verdict;
  const eqv = (name, got, want) => { if (got !== want) throw new Error(`${name}: got ${got}, want ${want}`); };

  /* MQTT: a type byte, then the remaining length, seven bits a byte. A
   * PUBLISH (type 3 in the top nibble) is two bytes of topic length, the
   * topic, then the message. */
  const varint = (n) => { const out = []; do { let b = n & 127; n >>= 7; if (n) b |= 128; out.push(b); } while (n); return out; };
  const publish = (topic, message) => { const body = [0, topic.length, ...text(topic), ...text(message)]; return [0x30, ...varint(body.length), ...body]; };
  const MQTT = `pattern ok = "sensors/";
    filter {
      frame (type = u8 @ 0, len = varint @ 1, head = 2) up to 4 {
        let kind = frame.type >> 4;
        if (kind == 3) {
          let topic = frame.data + 2;
          if (starts(topic, ok)) { count("published"); } else { decide rst("off_topic", 0); }
        }
      }
      decide pass;
    }`;

  yeet.test("varint: a one-byte length reads as the plain byte did", () => {
    eqv("allowed", v(MQTT, bytes(publish("sensors/a", "1"))), V.PASS);
    eqv("refused", v(MQTT, bytes(publish("valves/a", "1"))), V.RST);
  });
  yeet.test("varint: a two-byte length finds the topic one byte further on", () => {
    const big = "x".repeat(200);                                   // 211 bytes of body: 0xd3 0x01
    eqv("the length really is two bytes", publish("sensors/a", big)[1] & 128, 128);
    eqv("allowed", v(MQTT, bytes(publish("sensors/a", big))), V.PASS);
    eqv("refused", v(MQTT, bytes(publish("valves/a", big))), V.RST);
  });
  yeet.test("varint: the walk steps over a long record to the next one", () => {
    const big = "x".repeat(300);
    eqv("second record is judged", v(MQTT, bytes(publish("sensors/a", big), publish("valves/a", "1"))), V.RST);
    eqv("both fine", v(MQTT, bytes(publish("sensors/a", big), publish("sensors/b", "1"))), V.PASS);
  });
  yeet.test("varint: a three-byte length", () => {
    const huge = "y".repeat(20000);
    eqv("three length bytes", varint(20000 + 11).length, 3);
    eqv("refused", v(MQTT, bytes(publish("valves/a", huge).slice(0, 1500))), V.RST); // the topic is in the first segment
  });
  yeet.test("varint: frame.len is the decoded value", () => {
    const s = `filter { frame (len = varint @ 0, head = 1) up to 1 { if (frame.len == 321) decide drop("y"); } decide pass; }`;
    eqv("321", v(s, bytes(varint(321), new Array(8).fill(0))), V.DROP);
  });
  yeet.test("varint: a length that never ends, or runs off the data, stops the walk", () => {
    const s = `filter { frame (len = varint @ 0, head = 1) up to 2 { decide drop("ran"); } decide pass; }`;
    eqv("five continuation bytes", v(s, bytes([0xff, 0xff, 0xff, 0xff, 0x01, 1, 2, 3])), V.PASS);
    eqv("continuation, then nothing", v(s, bytes([0x80])), V.PASS);
    eqv("four bytes is the limit and works", v(s, bytes([0x81, 0x80, 0x80, 0x00, 9])), V.DROP);
  });
  yeet.test("varint: it must be the header's last byte", () => {
    const r = compile(`filter { frame (len = varint @ 0, type = u8 @ 3, head = 4) up to 1 { decide drop("x"); } decide pass; }`);
    if (r.ok || !/last byte of the header/.test(r.errors[0].text)) throw new Error(JSON.stringify(r.errors));
  });

  /* Postgres: a type byte, then a four-byte length that counts itself. */
  const pg = (type, body) => { const n = body.length + 4; return [type.charCodeAt(0), (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255, ...text(body)]; };
  const PG = `nocase; pattern drop_ = "drop ";
    filter {
      frame (type = u8 @ 0, len = be32 @ 1, adjust = -4, head = 5) up to 4 {
        if (frame.type == 'Q') { if (starts(frame.data, drop_)) decide rst("destructive", 0); count("q"); }
      }
      decide pass;
    }`;
  yeet.test("adjust: a length that counts its own four bytes", () => {
    eqv("select", v(PG, bytes(pg("Q", "select 1\0"))), V.PASS);
    eqv("drop", v(PG, bytes(pg("Q", "DROP TABLE t\0"))), V.RST);
    eqv("the second message lines up", v(PG, bytes(pg("Q", "select 1\0"), pg("Q", "drop table t\0"))), V.RST);
    eqv("a non-query message is stepped over", v(PG, bytes(pg("S", "drop table\0"), pg("Q", "select 1\0"))), V.PASS);
  });
  yeet.test("adjust: frame.len is the adjusted length, and the record ends there", () => {
    const s = `pattern x = "X"; filter { frame (type = u8 @ 0, len = be32 @ 1, adjust = -4, head = 5) up to 1 { if (frame.len != 3) decide drop("len"); if (within(frame.data, 64) & x) decide drop("leak"); } decide pass; }`;
    eqv("three bytes of body, the X after it is not in the record", v(s, bytes(pg("Q", "abc"), text("X"))), V.PASS);
  });
  yeet.test("adjust: a length smaller than what it claims to include ends the walk", () => {
    const s = `filter { frame (type = u8 @ 0, len = be32 @ 1, adjust = -4, head = 5) up to 2 { decide drop("ran"); } decide pass; }`;
    eqv("length 3 cannot include its own 4 bytes", v(s, bytes([81, 0, 0, 0, 3, 1, 2, 3])), V.PASS);
    eqv("length 4 is an empty body", v(s, bytes([81, 0, 0, 0, 4])), V.DROP);
  });
  yeet.test("adjust: positive, for a length that leaves part of the record out", () => {
    const s = `filter { frame (len = u8 @ 0, adjust = 2, head = 1) up to 2 { if (frame.len == 5) decide drop("y"); } decide pass; }`;
    eqv("3 + 2", v(s, bytes([3, 1, 2, 3, 4, 5])), V.DROP);
  });
}
