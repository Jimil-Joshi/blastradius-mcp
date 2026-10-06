# Contributing

Thanks for taking a look. This is a small TypeScript ESM project with two
runtime dependencies, so the bar for a good PR is low and the bar for a *correct*
PR is high — it is a security tool, and a detection bug is worse than a missing
feature.

## Requirements

- **Node.js 22 or newer.** Not a preference: the test suite relies on
  `node --test dist/tests/**/*.test.js`, and that glob is expanded by the Node
  test runner itself, which requires Node >= 22.
- npm 10+ (ships with Node 22).

CI runs Node 22 and 24 — the two active LTS lines.

## Setup

```bash
npm ci          # reproducible install from package-lock.json
npm run build   # tsc -> dist/
npm run test:src
```

`npm run test:src` builds first and then runs the compiled tests, so it is the
only command you need for a full local check. `npm test` runs the compiled
suite without rebuilding and will silently test stale output if you forget to
build.

Useful during development:

```bash
npm start -- --help     # CLI help: --version, --policy <file>, proxy --command "<cmd>"
```

## Layout

```
src/index.ts        CLI entry: flag parsing, proxy vs standalone mode
src/server.ts       MCP server: the six tools over stdio
src/analyzer/
  rules.ts          danger signatures (SH-/SQL-/CLD-/FS-)
  blastRadiusEngine.ts  scoring, severity bands, prod escalation
  dlpScanner.ts     DLP detectors and masking
src/policy/         policy rules and the ALLOW/BLOCK/REQUIRE_CONFIRMATION decision
src/proxy/          transparent proxy in front of another MCP server
src/security/       HMAC approval tokens, hash-chained audit ledger, edition gating
tests/*.test.ts     one test file per module, run via node --test
```

## Adding a detection rule

Danger signatures live in `src/analyzer/rules.ts` as entries in the
`DANGEROUS_RULES` array. IDs are prefixed by category and must never be reused:

| Prefix | Category | Example |
| :-- | :-- | :-- |
| `SH-` | Shell | `SH-001` (`rm -rf /`) |
| `SQL-` | SQL | `SQL-001` (`DROP DATABASE`) |
| `CLD-` | Cloud — AWS/GCP/Azure/K8s | `CLD-001` (`terminate-instances`) |
| `FS-` | Filesystem | `FS-001` (`.env`, `id_rsa`) |

Take the next free number in the block. Each entry needs a `pattern`,
`dangerScore` (0–100), `severity`, a `reason` written for a human, `destructive`
and `irreversible` flags, and `mitigations` that someone could actually follow.
`destructive` drives the dry-run simulation text; `irreversible` drives
`rollbackFeasible`, so getting those two wrong misreports reversibility.

A new signature:

1. **Must include a test** in the matching `tests/*.test.ts` — `blastRadiusEngine.test.ts`
   for `rules.ts` and `blastRadiusEngine.ts`, `dlpScanner.test.ts` for DLP
   detectors, `policyEngine.test.ts` for policy rules.
2. **Must include a false-positive note.** State in the PR description which
   legitimate commands or inputs your pattern could plausibly match, and why the
   score or severity is acceptable for them. If you can narrow the pattern to
   avoid them, do that instead of explaining it away.
3. Must keep the pattern anchored enough to avoid catastrophic backtracking on
   adversarial input, and must not be defeated by trivial obfuscation (extra
   whitespace, quoting, variable expansion).
4. Must not change the meaning of an existing rule without also updating the
   tests for it.

Adding a **DLP detector** follows the same pattern: an entry in `DLP_PATTERNS`
in `src/analyzer/dlpScanner.ts` with a `type`, `category`, `severity`, `pattern`,
and `maskPrefix`, plus a test in `tests/dlpScanner.test.ts`. Keep `type` names
stable — clients may match on them.

## Tests

- Tests are `node:test` + `node:assert/strict`, no framework.
- Name them for the behaviour, not the function:
  `BlastRadiusEngine - Evaluates rm -rf / as CRITICAL and destructive`.
- One assertion cluster per case. Assert on the specific field you care about
  (score, severity, decision), not on a whole object.
- No network access, no real cloud calls, no writes outside the repo.

## Commits and pull requests

- Branch from `main`: `fix/dlp-github-fine-grained-pat`, `docs/…`.
- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`,
  `ci:`. Imperative mood, one logical change per commit.
- PR descriptions explain *why*. For behavior changes, include before/after
  output of a real `simulate_action`, `inspect_payload_dlp`, or
  `enforce_policy` call.
- CI must be green on Node 22 and 24. CodeQL must report no new alerts.

## License

Contributions are accepted under the [Apache License 2.0](LICENSE). Two options:

- **Sign-off (recommended).** Append `-s` when you commit
  (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
  This is the DCO, and it is all this project asks for — there is no CLA to sign.
- **No sign-off is fine too.** Your contribution is licensed under Apache-2.0 by
  section 5 of the License, whether or not you sign off. If your employer needs
  a CLA for your contribution, open an issue first and we will sort it out.

Do not add a copyright header to files you did not substantially change.
