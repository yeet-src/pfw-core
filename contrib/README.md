# contrib

Programs that used to live in `examples/`. Every one **compiles** (checked in CI
by `test/node/examples.mjs`), but they are **not behaviour-tested**: nobody has
shown that each one fires on the attack it names and stays quiet on ordinary
traffic. Many are variations on one shape (scan → `any()` → strike count → ban).

Treat them as starting points, not as rules to deploy. Before relying on one,
write its test the way `test/node/examples-behavior.mjs` does for `examples/`: a
realistic positive input with the expected verdict and rule, realistic benign
traffic that must pass, and a shadow-mode run on real traffic.

The exceptions are the programs that were found broken and fixed; those have
regression tests in the same file (see its `CONTRIB_FIXED` list).

Things to check in any of them:

- **Plaintext only.** A payload scan cannot match on `:443`. These belong on the
  hop behind the TLS terminator.
- **`ban` bans the source address.** On a response-side rule (`sport == …`) the
  source is your own server.
- **Signature lists misfire.** Short patterns (`--`, `/*`, `;`, `..`) occur in
  ordinary headers and bodies; scope them with the cursor or require a second
  signal.
