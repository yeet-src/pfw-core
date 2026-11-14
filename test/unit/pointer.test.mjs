/* Pointers on the forward cursor — payload, find(ptr,'c',n), skip(ptr,'c'),
 * after(pattern), and starts on a derived pointer. These locate a field by
 * walking forward and then act in place, never copying. */
import { fromC, V } from "./helpers.mjs";

const v = (src, payload) => {
  const b = new TextEncoder().encode(payload);
  return fromC(src).run(b, {}, { dport: 80 }).verdict;
};
const eq = (g, w, m) => { if (g !== w) throw new Error(`${m}: got ${g}, want ${w}`); };

yeet.test("find advances to a byte; starts anchors there", () => {
  // walk to the '=', then compare at it ("=val...")
  const s = `pattern kv="=val"; filter { ptr p = find(payload, '=', 16); if (starts(p, kv)) decide drop("h"); decide pass; }`;
  eq(v(s, "key=value"), V.DROP, "'=' then val");
  eq(v(s, "keyXvalue"), V.PASS, "no '=' in range / no match");
});

yeet.test("skip eats a run of a byte", () => {
  const s = `pattern ok="ok"; filter {
    ptr p = find(payload, ' ', 32);
    skip(p, ' ');
    if (starts(p, ok)) decide drop("found");
    decide pass; }`;
  eq(v(s, "GET   ok"), V.DROP, "after the spaces comes ok");
  eq(v(s, "GET   no"), V.PASS, "after the spaces comes no");
});

yeet.test("after(pattern): cursor one past a match", () => {
  const s = `pattern host="Host:", bad="evil.test"; filter {
    ptr h = after(host);
    if (scan(h, 64) & bad) decide rst("blocked", 0);
    decide pass; }`;
  eq(v(s, "GET / Host: evil.test"), V.RST, "bad host after marker");
  eq(v(s, "GET / Host: good.test"), V.PASS, "good host");
});

yeet.test("a ptr initialized from payload is the whole buffer", () => {
  const s = `pattern g="GET"; filter { ptr p = payload; if (starts(p, g)) decide drop("h"); decide pass; }`;
  eq(v(s, "GET /"), V.DROP, "starts at 0");
  eq(v(s, "POST /"), V.PASS, "no");
});
