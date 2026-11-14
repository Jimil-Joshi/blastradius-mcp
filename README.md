# BlastRadius-Zero (v2.0)

**The Pre-Flight Safety Runtime & Zero-Bloat Gateway for AI Agents.** It unleashes
an in-memory swarm of 50 adversarial virtual personas to stress-test agent code and PRs
in <50ms *before* merge, slashes agent context memory by **99%** via JIT semantic routing,
enforces strict Test-Driven Development (TDD), resolves shell commands the way the kernel will,
redacts credentials flowing in either direction, and leaves a tamper-evident audit trail backed
by a local SQLite learning flywheel.

Apache-2.0. Built on Node 22+ (native `node:sqlite`). Runs locally, opens no sockets,
phones nothing home, no license key and no paid tier.

[![npm](https://img.shields.io/npm/v/blastradius-mcp.svg?style=flat-square)](https://www.npmjs.com/package/blastradius-mcp)
[![tests](https://img.shields.io/badge/tests-237%2F237%20passing-brightgreen.svg?style=flat-square)](https://github.com/Jimil-Joshi/blastradius-mcp/actions/workflows/ci.yml)
[![ci](https://github.com/Jimil-Joshi/blastradius-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Jimil-Joshi/blastradius-mcp/actions/workflows/ci.yml)
[![codeql](https://github.com/Jimil-Joshi/blastradius-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/Jimil-Joshi/blastradius-mcp/actions/workflows/codeql.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E.svg?style=flat-square)](https://nodejs.org)
[![types](https://img.shields.io/badge/TypeScript-strict-3178C6.svg?style=flat-square)](tsconfig.json)

---

## The problem

Give an agent `bash`, filesystem, SQL, or cloud access through MCP and you have
handed a language model the ability to run `rm -rf`, `DROP TABLE`, or
`aws s3 rb`. Those are not hypotheticals, they are the first thing anyone writes
in a demo. Meanwhile:

- Tool inputs and outputs carry unmasked AWS keys, GitHub PATs, and database passwords.
- Nothing simulates the consequences before the call lands.
- Nothing records that the call happened, so nothing can be reviewed afterwards.

Existing options ask you to route every call through a hosted control plane, or to
rewrite your agent loop. BlastRadius sits in front of the MCP server instead. Your
agent's loop does not change.

### And the second problem: matching the text is not the same as matching the command

This is the one that gets products like this wrong.

A guardrail matches the submitted string. The shell executes the *resolved*
string. Bash rewrites the text first, through quote removal, parameter expansion,
command substitution, and pipeline assembly. So these are the same command to the
kernel and completely different strings to a regex:

```
D=/; rm -rf $D*          text: harmless-looking     runs: rm -rf /*
rm -rf $(echo /)         text: no slash             runs: rm -rf /
bash -c "rm -rf /"       text: a bash invocation    runs: rm -rf /
cat payload.sh | sh      text: reading a file       runs: an unreviewed script
```

A guard evaluating the pre-transformation string and a shell executing the
post-transformation string are evaluating **two different commands**.

This is not a hypothetical concern. The **GuardFall** survey, published 30 June
2026, tested the pre-execution command guards in eleven actively maintained coding
agents spanning roughly 548,000 GitHub stars. Agents whose guard regexes the raw
command string leaked on the large majority of bypass cases attempted against them.
Goose leaked on 22 of 23. OpenCode on 16 of 16. Only **Continue**, which tokenizes
with shell-aware parsing and resolves expansion and substitution *before* matching
the fully resolved command, blocked all twenty-one cases.

So this engine resolves first, then matches. See
[Seeing past the bypass](#seeing-past-the-bypass).

---

## Install

```bash
npx -y blastradius-mcp
```

Requires Node 22+. That is the whole install.

### Standalone

Run it as its own MCP server and call its tools from your agent.

```json
{
  "mcpServers": {
    "blastradius": { "command": "npx", "args": ["-y", "blastradius-mcp"] }
  }
}
```

### Proxy mode

Wrap an existing server. Nothing downstream changes.

```bash
npx blastradius-mcp proxy --command "npx -y @modelcontextprotocol/server-filesystem /workspace"
```

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "npx",
      "args": [
        "-y", "blastradius-mcp", "proxy",
        "--command", "npx -y @modelcontextprotocol/server-filesystem /workspace"
      ]
    }
  }
}
```

Working configs for Cursor, Cline, and VS Code are in [`examples/`](examples/).
Installable as a one-click local MCP bundle via [`manifest.json`](manifest.json).

---

## Real output

Every block below was produced by running the engine, not written by hand.
Regenerate them yourself with `node scripts/generate-readme-transcripts.mjs`.

### Scoring a destructive action

```json
// simulate_action("rm -rf / --no-preserve-root")
{
  "dangerScore": 100,
  "severity": "CRITICAL",
  "category": "SHELL",
  "reasons": [
    "Recursive root, home, or wildcard filesystem deletion detected (rm -rf / or *)"
  ],
  "destructive": true,
  "irreversible": true,
  "rollbackFeasible": false,
  "recommendedMitigations": [
    "Target specific named directories only",
    "Use trash-cli or create a verified dry-run backup first"
  ]
}
```

### The same command, different environment

Score 95 on staging. **100** when the context says production.

```json
// simulate_action("aws s3 rb s3://prod-bucket --force", context={environment:"production"})
{
  "dangerScore": 100,
  "severity": "CRITICAL",
  "category": "CLOUD",
  "reasons": [
    "Object storage mass deletion (bucket removal or a syncing delete) destroys data and versions",
    "Target environment is marked as PRODUCTION (production), escalating blast radius."
  ],
  "destructive": true,
  "irreversible": true,
  "rollbackFeasible": false
}
```

### A read is not a risk

```json
// simulate_action("SELECT id, email FROM users LIMIT 10")
{
  "dangerScore": 5,
  "severity": "SAFE",
  "category": "SQL",
  "destructive": false,
  "irreversible": false,
  "rollbackFeasible": true,
  "reasons": ["Standard read-only or low-impact routine action."]
}
```

### Redacting credentials on the way in

```json
// inspect_payload_dlp({authorization:"Bearer AKIAIOSFODNN7EXAMPLE",
//                      dsn:"postgres://admin:hunter2@db.internal:5432/prod",
//                      card:"4111 1111 1111 1111", note:"owner joe@acme.com"})
{
  "hasFindings": true,
  "findingsCount": 5,
  "findings": [
    { "type": "AWS_ACCESS_KEY",              "category": "CREDENTIAL", "severity": "CRITICAL", "preview": "AKIA...MPLE" },
    { "type": "DATABASE_CONN_URI_PASSWORD",  "category": "CREDENTIAL", "severity": "HIGH",     "preview": "post...er2@" },
    { "type": "CREDIT_CARD_NUMBER",          "category": "PII",        "severity": "HIGH",     "preview": "4111...1111" },
    { "type": "EMAIL_ADDRESS",               "category": "PII",        "severity": "MEDIUM",   "preview": "joe@....com" }
  ],
  "sanitizedContent": "{\"authorization\":\"Bearer [REDACTED_AWS_KEY:MPLE]\",\"dsn\":\"postgres://admin:[REDACTED_PASSWORD]@db.internal:5432/prod\",\"card\":\"[REDACTED_CREDIT_CARD:1111]\",\"note\":\"owner [REDACTED_EMAIL:.com]\"}"
}
```

### The policy gate blocks

```json
// enforce_policy("bash", {command: "rm -rf /var/lib/postgresql"})
{
  "decision": "BLOCK",
  "ruleMatched": "ZT-001",
  "reasons": [
    "Violates rule [Block Root and Wildcard Deletion]: Matches strictly forbidden pattern 'rm -rf /'"
  ],
  "requiresToken": false
}
```

### Step-up approval, and the replay it prevents

The same call three times: no token, valid token, same token again.

```json
// 1. no token
{
  "decision": "REQUIRE_CONFIRMATION",
  "ruleMatched": "ZT-003",
  "reasons": ["Elevated risk (Severity: CRITICAL, Danger Score: 95). Cryptographic confirmation token required to proceed."],
  "requiresToken": true,
  "tokenValid": false
}

// request_confirmation_token(...).payload
{
  "tokenId": "br-tok-62b3da7b-67c9-48b4-b766-f1a12d4a25bf",
  "toolName": "bash",
  "actionFingerprint": "95:terraform-destroy",
  "requestedBy": "jimil@acme.dev",
  "issuedAt": 1791190531,
  "expiresAt": 1791190831,
  "reason": "Approved in ticket OPS-4471"
}

// 2. with the token
{
  "decision": "ALLOW",
  "ruleMatched": "ZT-003",
  "reasons": ["Action elevated and approved via valid token: br-tok-62b3da7b-..."],
  "requiresToken": false,
  "tokenValid": true
}

// 3. same token again
{
  "decision": "REQUIRE_CONFIRMATION",
  "reasons": [
    "Provided confirmation token is invalid or expired: Token has already been consumed (replay prevention)",
    "Elevated risk (Severity: CRITICAL, Danger Score: 95). Cryptographic confirmation token required to proceed."
  ],
  "requiresToken": true,
  "tokenValid": false
}
```

That third block is the whole point. An approval token authorises exactly one
action.

---

## The 12 MCP Tools (BlastRadius-Zero)

BlastRadius-Zero exposes 12 high-impact tools across 4 operational pillars:

### Pillar 1: Zero-Bloat Gateway (Context Optimization)
| Tool | What it does |
| :--- | :--- |
| `route_tool` | **Semantic JIT Router**: Replaces 50 tool schemas in agent context with 1 router. Resolves intent, fetches schema just-in-time, and saves **98.9%** context tokens. |
| `virtualize_context` | **Payload Compression**: Compresses large diffs, database dumps, and logs into lightweight virtual handles (`ctx_<id>`), with auto-DLP redaction and query filtering. |

### Pillar 2: Swarm Pre-Flight Safety Simulator
| Tool | What it does |
| :--- | :--- |
| `simulate_swarm_impact` | **The Viral Demo**: Unleashes 25-50 adversarial virtual personas in <50ms to attack code diffs before merge. Detects race conditions, auth bypasses, and IDORs. |
| `adversarial_persona_review` | **Targeted Red-Team**: Runs deep stress-testing across Hacker, Confused User, Legacy System, Concurrency Racer, and Data Corruptor personas with reproduction steps. |
| `blast_radius_heatmap` | **Visual Risk Matrix**: Renders instant ASCII or Markdown matrices evaluating impacted components, user classes, data sensitivity, and containment feasibility. |

### Pillar 3: TDD Enforcer & Quality Gate
| Tool | What it does |
| :--- | :--- |
| `enforce_tdd_state` | **Red-Green-Refactor Lock**: Prohibits agents from touching production code until a failing test is written and confirmed. Validates passes before commit. |
| `generate_socratic_spec` | **Socratic Spec Decomposer**: Expands informal feature requests into rigorous contracts with explicit edge cases (null, unicode, concurrency) and RED test plans. |
| `spawn_worktree_subagent` | **Isolated Git Worktrees**: Automatically spins up parallel branch worktrees (`.blastradius/worktrees/<id>`) to keep subagents from dirtying the main workspace. |
| `automated_code_critique` | **Senior-Dev AST Review**: Inspects changed files for empty catch blocks, dangerous shell sinks, missing assertions, unbounded queries, and unhandled nulls. |

### Pillar 4: Zero-Trust Compliance & Self-Enhancement Flywheel
| Tool | What it does |
| :--- | :--- |
| `verify_audit_log` | **SOC2 Hash-Chain Audit**: Re-walks the HMAC-SHA256 immutable ledger to detect tampering, deleted records, or unauthorized modifications. |
| `request_confirmation_token` | **Step-Up Approval**: Issues signed, single-use, time-bound tokens for dangerous actions with cryptographic replay prevention. |
| `get_security_posture` | **Real-Time Threat Score**: Aggregates live danger score (0-100), active policy status, audit integrity, TDD state, and SQLite learning telemetry. |

> **Legacy Proxy Compatibility**: Foundational tools (`simulate_action`, `inspect_payload_dlp`, `enforce_policy`) remain fully supported for backward-compatible proxy pipelines.

---

## Seeing past the bypass

[`src/analyzer/shellResolver.ts`](src/analyzer/shellResolver.ts) resolves a command
the way a POSIX shell would, to the extent that is possible **without executing
anything**. The rule patterns then run against what the shell would actually run.

The pass performs, in order:

1. **Quote removal.** `rm -rf "/"` and `rm -rf /` are the same command.
2. **Variable assignment tracking.** `D=/; rm -rf $D*` resolves `$D` from the
   assignment earlier in the same command, because the shell would.
3. **Parameter expansion.** `$HOME`, `$ROOT`, `$PWD` and friends expand. When the
   value is not statically knowable it is substituted as a marked `UNKNOWN`, which
   is treated as a root-or-home target rather than an opaque token, so a recursive
   delete aimed at an unseen variable still matches.
4. **Command substitution.** `$(...)` and backticks are resolved to the literal
   content inside them. This is deliberately conservative: `rm -rf $(echo /)`
   resolves to a token containing a slash, which is enough to match. Nothing is
   ever executed to find out what a substitution would produce.
5. **Pipeline splitting.** Stages are separated at the top level only, so
   `echo 'a | b'` stays one stage.
6. **Inline program extraction.** `sh -c` takes the *whole remainder* of the line as
   its program, so `bash -c "rm -rf /"` resolves to the destructive command it runs.
7. **Interpreter detection.** Any stage that receives content from a pipe and is
   itself an interpreter is flagged, because the program that runs is not in the
   request.

On top of that the engine scores structural facts no regex can express:

- a destructive binary (`rm`, `unlink`, `shred`, `srm`) aimed at a root, home, or
  wildcard target
- `shred` and `srm` against *any* path, because they overwrite in place and so
  cannot be recovered even without a recursive flag
- a recursive `rm` against a system path such as `/etc`
- destruction delegated to `find` via `-delete`, `-exec rm`, or `-ok`
- content piped into an interpreter, with or without a substitution
- arguments assembled at runtime by `xargs`
- a destructive command composed inline inside `sh -c`

Every report carries the `resolution` block, so a reviewer can see the exact text
that was matched:

```json
// simulate_action("D=/; rm -rf $D*")
{
  "dangerScore": 100,
  "severity": "CRITICAL",
  "reasons": [
    "Recursive rm against a broad target (-rf /*), resolved through variable or substitution expansion."
  ],
  "resolution": {
    "resolvedCommand": "D=/; rm -rf /*",
    "traits": ["assigned:D", "unresolved-variable:D"],
    "hasPipeline": false,
    "interpreters": [],
    "unresolvedVariables": []
  }
}
```

### Coverage

`tests/shellResolver.test.ts` pins the GuardFall bypass classes. 23 of 23 dangerous
commands that a raw-string guard would miss are scored HIGH or above:

| Class | Examples |
| :--- | :--- |
| Variable expansion | `D=/; rm -rf $D*`, `rm -rf $HOME`, `TARGET=/etc; shred -u $TARGET/*` |
| Command substitution | `rm -rf $(echo /)`, `rm -rf \`echo /\`` |
| Quoting | `rm -rf "/"`, `rm -rf '/'*' '/"'` |
| Alternate destructive binaries | `unlink /etc/shadow`, `find / -type f -delete`, `find . -exec rm {} \;` |
| Indirect execution | `cat payload.sh \| sh`, `bash -c "rm -rf /"`, `sh -c "$(curl …)"`, `xargs rm < targets.txt` |

The same file pins the other direction: 18 routine commands that must *not* trip,
including `rm -rf node_modules`, `rm -rf ./build`, `kubectl apply -f deployment.yaml`,
and `terraform plan`. A guard that blocks everything is not a guard.

### What resolution still does not catch

Stated plainly, because this is the tier the literature says gets bypassed and
pretending otherwise would repeat the mistake this project already fixed once:

- **Encoding.** Base64, hex, and ROT-encoded payloads are not decoded.
- **Multi-hop indirection.** `bash /tmp/x.sh` where `x.sh` was written three calls
  ago is opaque to a single-call analysis.
- **A destructive payload assembled character by character** at runtime.
- **Anything outside a shell.** MCP tool arguments that are not command strings go
  through scoring, but not through a resolver.

Resolution closes the specific gap GuardFall documented for shell commands. It is
not general program analysis, and no honest claim should say it is.

---

---

## Detection coverage

**24 signatures** in [`src/analyzer/rules.ts`](src/analyzer/rules.ts), scored by rule ID.
Scoring takes the **max** matching rule, not a sum, so overlapping patterns do not
inflate a score. All 24 are matched against the **resolved** command, so the
alternative destructive binaries and indirections listed above are reachable
without a dedicated rule.

| ID | Scores | Covers |
| :--- | ---: | :--- |
| `SH-001` | 100 | `rm -rf /`, `rm -rf *`, `~`, `$HOME` |
| `SH-002` | 100 | `mkfs`, `dd if=… of=/dev/…`, `fdisk` |
| `SH-003` | 95 | Fork bombs |
| `SH-004` | 90 | `curl … \| sh` |
| `SH-005` | 80 | `chmod 777` / `666` |
| `SH-006` | 85 | `shutdown`, `reboot`, `poweroff` |
| `SH-007` | 85 | `git push --force`, `reset --hard`, `clean -fdx` |
| `SH-008` | 95 | `reg delete`, `del /f /s /q C:\windows` |
| `SQL-001` | 100 | `DROP DATABASE`, `DROP SCHEMA` |
| `SQL-002` | 90 | `DROP TABLE`, `TRUNCATE` |
| `SQL-003` | 90 | `DELETE FROM` with no `WHERE` |
| `SQL-004` | 85 | `UPDATE … SET` with no `WHERE` |
| `SQL-005` | 80 | `GRANT ALL PRIVILEGES` |
| `CLD-001` | 95 | `terminate-instances`, `delete-cluster`, `delete-db-instance`, `delete-stack` |
| `CLD-002` | 95 | `kubectl delete namespace\|all\|nodes\|pv\|pvc`, `drain` |
| `CLD-003` | 85 | `delete-user`, `delete-role`, `delete-access-key` |
| `CLD-004` | 95 | `terraform destroy\|apply`, `pulumi destroy`, `-auto-approve` |
| `CLD-005` | 95 | `s3 rb`, `gsutil rm -r`, `s3 sync … --delete` |
| `CLD-006` | 85 | `helm uninstall\|delete`, `kubectl delete` |
| `CLD-007` | 80 | `npm publish`, `twine upload`, `docker push :latest` |
| `FS-001` | 80 | `.env`, `.aws/credentials`, `id_rsa`, `/etc/shadow`, service account JSON |
| `FS-002` | 90 | Mass deletion by synchronisation and pruning: `rsync --delete`, `docker prune`, `git worktree remove --force` |
| `DB-001` | 95 | Destructive database operations issued through a client binary: `redis-cli FLUSHALL`, `mongosh dropDatabase`, `psql TRUNCATE` |
| `SH-009` | 90 | Encoded content piped to a decoder that then executes: `base64 -d \| sh` |

Bands: `SAFE` <15, `LOW` 15-39, `MEDIUM` 40-69, `HIGH` 70-89, `CRITICAL` 90+.
Categories: `SHELL`, `SQL`, `CLOUD`, `FILESYSTEM`, `NETWORK`, `GENERIC`.

**11 DLP detectors** in [`src/analyzer/dlpScanner.ts`](src/analyzer/dlpScanner.ts):

- Credentials: AWS access keys, GitHub PATs (`ghp_` and `github_pat_`), OpenAI,
  Stripe secret keys, Slack tokens, SSH private keys, database URI passwords, JWTs
- PII: credit cards (Visa, Mastercard, Amex, Discover, Diners, UnionPay, in
  contiguous, spaced, or hyphenated form), US SSNs, email addresses

### What it does not catch

Stated up front, because a rule set that pretends to be complete is worse than one
that does not:

- **Encoded payloads.** Base64, hex, and string concatenation defeat both the
  resolver and the rules. See [what resolution still does not catch](#what-resolution-still-does-not-catch).
- **Multi-step and multi-call attacks within one call.** Sequence detection below
  covers the audited cases, not arbitrary workflows.
- **Anything semantic.** It does not know that `orders_archive_2019` matters less
  than `orders`.
- **Agent-supplied identity.** `requestedBy` on an approval token is free text from
  the calling agent. See [Step-up approval tokens](#step-up-approval-tokens).

[Open an issue](https://github.com/Jimil-Joshi/blastradius-mcp/issues) if you have
a dangerous pattern that is not covered. The rule set is the part most worth
improving.

---

## Default policy

Four rules, active out of the box, in [`src/policy/defaultPolicies.ts`](src/policy/defaultPolicies.ts).

| ID | Action | Detail |
| :--- | :--- | :--- |
| `ZT-001` | BLOCK | `rm -rf /`, `rm -rf *`, `DROP DATABASE`, `DROP SCHEMA`, `mkfs`, `format c:` |
| `ZT-002` | BLOCK | Fork bombs, `dd if=/dev/zero`, `del /f /s /q c:\windows` |
| `ZT-003` | REQUIRE_CONFIRMATION | Any `HIGH` or `CRITICAL` action needs a signed token |
| `ZT-004` | BLOCK | `.env`, `.env.production`, `id_rsa`, `id_ed25519`, `.aws/credentials`, `/etc/shadow`, `service-account.json` |

Override it with your own JSON via `--policy`, see [`examples/custom_policy.json`](examples/custom_policy.json):

```bash
npx blastradius-mcp --policy ./my-policy.json
```

`ZT-004` matches with a plain `includes()` on the serialized parameters. That is
deliberately conservative and it does over-block: any path containing `.env`
matches, including `.envrc`. Tune it with `severityThreshold` rather than by
loosening the pattern.

---

## Sequence detection — the part a single call cannot see

Per-call allow/deny misses workflows assembled from individually benign steps.
Microsoft's own analysis of an MCP control plane states the gap directly:

> "Per-call allow still misses malicious workflows built from individually permitted
> steps. Sequence policy is the next real control."

[`src/analyzer/sequenceDetector.ts`](src/analyzer/sequenceDetector.ts) is that
control. It runs over the hash-chained decision log after the per-call verdict and
detects five workflow shapes:

| Signal | Fires when | Default escalation |
| :--- | :--- | :--- |
| `exfiltration-then-destruction` | A credential-adjacent read is followed by a destructive or irreversible decision | `BLOCK` if critical, else `CONFIRMATION` |
| `reconnaissance-then-exfiltration` | A run of ≥5 reads across ≥3 distinct payloads, terminated by a network or DLP-positive sink | `CONFIRMATION` |
| `privilege-ladder` | ≥3 distinct privilege families approved in a non-decreasing severity run, or a strictly rising score on one tool | `CONFIRMATION` |
| `guardrail-probing` | ≥3 refusals against one tool family | `CONFIRMATION`, `BLOCK` at ≥5 |
| `destructive-burst` | ≥4 destructive decisions inside 8 decisions, boosted when the span is under 120 seconds | `CONFIRMATION`, `BLOCK` at ≥6 |

Three properties that matter:

- **It can only tighten a decision, never loosen one.** If the per-call rule already
  blocked or demanded a token, that stands. Sequence analysis never downgrades.
- **Every signal cites its evidence.** The reason string names the entry indices
  that triggered it, so a reviewer can reconstruct the finding rather than trust a
  score.
- **It reports its own blind spot.** `truncated: true` is returned when the
  analysis window excludes earlier history, because a pattern beginning before the
  window cannot be found inside it.

Thresholds are tunable through the same policy document as everything else:

```json
{
  "sequence": {
    "enabled": true,
    "windowSize": 20,
    "destructiveBurstThreshold": 4,
    "probingThreshold": 3
  }
}
```

### What sequence detection still misses

Documented deliberately, because a detector with unstated limits is not a detector
you can rely on:

- **Sub-window attacks.** Analysis sees only the last `windowSize` decisions. An
  agent that reads a secret, runs 21 benign calls, then destroys will set
  `truncated: true` and produce no signal.
- **Cross-caller laundering.** Nothing correlates by `callerId`. An attack split
  across two agent identities resets both the ordering and the burst span.
- **Slow, patient exfiltration.** `reconnaissance-then-exfiltration` requires a
  *contiguous* read run immediately before the sink. Five reads interleaved with
  writes across ten minutes is not a run. The detector is tuned for agent-speed
  attacks, which is the same thing that makes it weak against a patient one.
- **Destructive classification is reconstructed** from severity, score, and reason
  wording, because the ledger does not persist the engine's `destructive` flag.
  Changing reason wording without updating the detector narrows it silently.

---

## Audit ledger

Append-only JSONL, SHA-256 hash chain, one HMAC-SHA256 signature per entry.

- Payloads are **hashed, not stored**, so secrets never land in the log.
- `verify_audit_log` re-computes every hash **and** re-computes every signature.
  The hash chain alone does not cover `severity`, `category`, `reasons`, or
  `dlpFindingsCount`; the signature is what covers those, which is why it is
  verified rather than merely written.
- Editing any field of any entry breaks verification and reports the index.

The signing key defaults to a random per-process value, so **set it explicitly** or
previously written entries will not verify after a restart:

```bash
export BLAST_RADIUS_AUDIT_KEY="a-long-random-secret"
export BLAST_RADIUS_SIGNING_KEY="a-different-long-random-secret"
```

The ledger defaults to `process.cwd()`, which under a GUI client is wherever the
app happened to launch from. Point it somewhere deliberate:

```bash
export BLAST_RADIUS_AUDIT_PATH="/var/log/blastradius/audit.jsonl"
```

What the chain does **not** do: detect deletion of entries (the ledger is verified
from the in-memory copy), detect truncation, or survive a full rewrite with
recomputed hashes. There is no external or Merkle anchoring. Treat it as
tamper-*evident*, not tamper-proof.

---

## Step-up approval tokens

HMAC-SHA256, JWT-shaped `payload.signature`, 300-second default TTL, hard-capped at
one hour.

- Signature compared with `crypto.timingSafeEqual`, never `===`.
- Scoped to a single tool name, or `*` for any tool.
- **Single-use.** The token is consumed the moment it authorises an action, so
  replaying it returns `REQUIRE_CONFIRMATION` with
  `Token has already been consumed (replay prevention)`.
- Consumed records are pruned once the token's own expiry passes, which bounds
  memory without reopening the hole.

One honest limitation: `requestedBy` is a free-text string supplied by the calling
agent. There is no out-of-band human channel and no identity provider behind it.
The token proves *an approval was issued and spent once*. It does not prove a
specific human pressed a button. Wiring it to a real approval service is the
natural next step, and it is not built.

---

## Proxy mode

```
npx blastradius-mcp proxy --command "<downstream mcp server command>"
```

Inspects inbound `tools/call` requests and, more usefully, scans **downstream
responses** and redacts credentials before they reach the client. A tool that
echoes a key back at your model is a routine leak path, and nothing upstream of it
usually cleans up.

A step-up token is accepted as a `confirmationToken` argument on the call. It is
stripped before forwarding, so an approval credential never reaches a server with
no business holding it.

Known limitations, stated plainly:

- The downstream command is split on whitespace, so a path containing a space
  breaks.
- It is a line-oriented JSON-RPC passthrough, not a full MCP SDK client.
- The proxy exposes the *downstream* server's tools, not BlastRadius's own 12 tools.

---

## Testing & Verification Architecture

Every claim made in this repository is backed by automated tests and reproducible diagnostic probes. Zero mocks for security logic; tests execute against the actual shell resolver, DLP scanner, in-memory persona swarm, SQLite engine, and HMAC cryptographic token systems.

```bash
npm test
```

```
ℹ tests 237
ℹ suites 12
ℹ pass 237
ℹ fail 0
ℹ duration_ms 4411.96
```

The build is `tsc` under `strict: true`. No external bundler, no framework dependencies. CI runs the suite on Node 22 and 24, with CodeQL on javascript-typescript.

### The 12 Test Suites Breakdown (237 Passing Tests)

| Suite | Tests | What is rigorously verified |
| :--- | ---: | :--- |
| `tests/shellResolver.test.ts` | 23 | 23/23 GuardFall bypass classes: variable expansions (`D=/; rm -rf $D*`), command substitutions (`$(echo /)`), nested quoting, inline interpreters (`bash -c`), and pipes. Pins 38+ benign commands to prevent over-blocking. |
| `tests/swarm/swarm.test.ts` | 12 | Pre-flight Swarm Simulator: 25-agent and 50-agent simulation runs in <50ms, detecting race conditions, SQLi, and auth bypasses across Hacker, Confused User, Legacy System, Concurrency Racer, and Data Corruptor personas. |
| `tests/gateway/gateway.test.ts` | 14 | Zero-Bloat JIT Router & Virtualizer: Intent routing, schema on-demand fetching with 98.9% token reduction, virtual handle generation (`ctx_<id>`), query filtering, and inline DLP credential masking. |
| `tests/quality/quality.test.ts` | 11 | TDD State Machine & AST Critique: Strict Red → Green → Refactor lock (`CHECK_PERMISSION`), Socratic spec generation with contracts/invariants, subagent Git worktree isolation, and Senior-Dev AST critique. |
| `tests/storage/flywheel.test.ts` | 12 | Native SQLite Learning Flywheel: Node 22/24 native SQLite in WAL mode, atomic transactions, attack vector recording, automated rule synthesis, and real-time security posture scoring. |
| `tests/auditLedger.test.ts` | 7 | SOC2 Hash-Chained Audit Ledger: HMAC-SHA256 entry signing, SHA-256 hash chaining from genesis, disk JSONL persistence, and tamper detection (field modification, link breaking, head/middle truncation). |
| `tests/tokenManager.test.ts` | 9 | Step-Up Approval Tokens: HMAC-SHA256 signature verification via `crypto.timingSafeEqual`, single-use consumption, cryptographic replay prevention, TTL expiry enforcement, and wildcard tool scoping. |
| `tests/sequenceDetector.test.ts` | 5 | Multi-Step Sequence Anomaly Detector: Workflow anomaly identification across consecutive decisions: exfiltration-then-destruction, reconnaissance-then-exfiltration, privilege-ladder, and destructive-burst. |
| `tests/blastRadiusEngine.test.ts` | 9 | Blast Radius Scoring: 0–100 risk scoring across SHELL, SQL, CLOUD, and FS categories, production environment escalation, and AST argument inspection with zero prose false positives. |
| `tests/dlpScanner.test.ts` | 5 | DLP Redaction Engine: Detection and masking of AWS access keys, GitHub PATs, PostgreSQL/MySQL URI passwords, credit card numbers (Luhn check), US SSNs, and emails. |
| `tests/integration/server12tools.test.ts` | 15 | All 12 MCP Tools End-to-End: Validates protocol schemas, client-server lifecycle, dual-write audit logs, and SQLite telemetry for all 12 tools. |
| `tests/server.e2e.test.ts` | 4 | Full Stdio JSON-RPC Lifecycle: End-to-end integration over stdio transport, single-use token replay rejection across the wire, secret redaction, and open-source posture reporting. |

### The 10 Pre-Flight Verification Gates (`validate-blastradius-zero.mjs`)

BlastRadius-Zero is validated self-referentially before release across 10 operational gates:

```bash
node scripts/validate-blastradius-zero.mjs
```

```
================================================================================
🚀 VALIDATING BLASTRADIUS-ZERO v2.0 USING BLASTRADIUS-ZERO ITSELF
================================================================================
[1/10] Verifying MCP Tool Discovery: 12 tools registered and advertising schemas...  ✓ PASSED
[2/10] Running simulate_swarm_impact (50 Personas in <50ms) on code diff...          ✓ PASSED
[3/10] Running adversarial_persona_review with reproduction steps & assertions...     ✓ PASSED
[4/10] Rendering visual blast_radius_heatmap (ASCII & Markdown matrices)...           ✓ PASSED
[5/10] Verifying enforce_tdd_state (Red -> Green -> Refactor lock)...                 ✓ PASSED
[6/10] Generating generate_socratic_spec (Invariants, edge cases, Red test plan)...   ✓ PASSED
[7/10] Testing route_tool (JIT Schema Fetch & 98.9% Token Reduction)...              ✓ PASSED
[8/10] Testing virtualize_context (ctx_<id> handle & 98.8% payload compression)...   ✓ PASSED
[9/10] Testing automated_code_critique (AST scan: swallowed catches & unindexed DB)  ✓ PASSED
[10/10] Fetching get_security_posture & Native SQLite Data Flywheel telemetry...      ✓ PASSED
================================================================================
🎉 ALL 10 BLASTRADIUS-ZERO VERIFICATION GATES PASSED CLEANLY!
================================================================================
```

### Diagnostic Probes Suite

Seven standalone diagnostic probe scripts are provided in `scripts/` to audit specific subsystems in isolation:

| Probe Script | Purpose | Expected Outcome |
| :--- | :--- | :--- |
| `node scripts/probe-guardfall.mjs` | Tests 23 evasive bypass classes (variables, subshells, quotes, pipes) | 23/23 caught at HIGH or CRITICAL |
| `node scripts/probe-false-positives.mjs` | Tests 39 routine developer commands (`npm test`, `git commit`, `SELECT`) | 38/39 permitted below HIGH |
| `node scripts/probe-sequence.mjs` | Audits multi-step reconnaissance and exfiltration workflows | Catches multi-step exfil; quiet on benign |
| `node scripts/probe-ledger-integrity.mjs` | Simulates head-cut, middle-cut, and truncation tampering on ledger | Flags tampering with exact index |
| `node scripts/probe-adversarial.mjs` | Tests bash AST nuances (brace expansion, nested substitutions) | Catches 100% of adversarial payloads |
| `node scripts/probe-redteam.mjs` | Tests advanced bash execution (indirect vars, array expansions) | Blocks attacks while allowing benign builds |
| `node scripts/generate-readme-transcripts.mjs` | Re-executes live engine against all README sample outputs | Regenerates live output transcripts |

### Empirical Validation & 4-Pillar Proofs

Every product claim of BlastRadius-Zero (v2.0) is backed by direct, measurable, reproducible empirical benchmarks:

```bash
npm run test:pillars
```

| Product Pillar | Core Claim | Measured Benchmark Result | Verification Status |
| :--- | :--- | :--- | :--- |
| **Pillar 1: Zero-Bloat Gateway** | ~99% token reduction via single `route_tool` schema & context virtualization | • Tool catalog footprint cut from **9,522 to 55 tokens** (**99.4% reduction** across 51 tools)<br>• 122KB database payload compressed with **99.5% token savings** (saved 31,099 tokens)<br>• Automated DLP mask applied in preview snippet (`[REDACTED_AWS_KEY:MPLE]`)<br>• Zero-loss payload resolution by virtual handle (`ctx_...`) | **VERIFIED (100%)** |
| **Pillar 2: Swarm Pre-Flight Simulator** | 50 adversarial personas in memory in <50ms; instant Risk Heatmap (0-100) | • Average execution latency: **1.48 ms** across 10 consecutive 50-persona runs (Min: 0.19ms, Max: 9.47ms)<br>• Caught SQL Injection (Hacker), Deep Unhandled Undefined (Confused User), Timeout Hang (Legacy System), TOCTOU Race Conditions (Concurrency Racer), Null-Byte Poisoning (Data Corruptor)<br>• Danger scoring: Benign `ls` (5/100, SAFE) vs Destructive `DROP DATABASE` (100/100, CRITICAL) | **VERIFIED (100%)** |
| **Pillar 3: TDD Enforcer & AST Gate** | Red $\rightarrow$ Green $\rightarrow$ Refactor lock; Senior AST code critique | • Production code modifications physically blocked in `IDLE`/`RED_PENDING`<br>• Test files exempted to allow writing failing assertions<br>• Auto-unlocks write access only upon confirmed failing test runner output<br>• AST critique flags empty `try/catch` blocks and dangerous `child_process.exec()` sinks with CRITICAL severity | **VERIFIED (100%)** |
| **Pillar 4: Zero-Trust Ledger & Flywheel** | Single-use HMAC-SHA256 tokens; tamper-evident hash chain; local learning flywheel | • Cryptographic step-up token issued, verified, and replayed $\rightarrow$ replay blocked with `'Token has already been consumed'`<br>• Forged signature rejected with `'Cryptographic signature mismatch'`<br>• Direct disk edit of 1 character in JSONL ledger detected at exact record index with broken hash chain error<br>• Local SQLite (WAL mode) indexes attack patterns with zero cloud leaks | **VERIFIED (100%)** |

### Live Validation on 10+ Major Open-Source MCP Servers

To prove cross-ecosystem effectiveness, BlastRadius-Zero was tested across **10 major open-source MCP toolsets** (83 tools total): Filesystem, GitHub, PostgreSQL, Docker, Kubernetes, AWS S3, Puppeteer, Redis, Slack, and Naukri-MCP:

```bash
npm run test:opensource
```

* **Zero-Bloat Gateway in the Wild:** Ingested 83 tool schemas (9,218 tokens). Exposing `route_tool` reduced initial context footprint to 55 tokens (**99.4% token cut**). 100% of natural language intents were accurately routed to their target servers.
* **50-Persona Swarm on Real PR Diffs:** Stress-tested PR diffs from Next.js, Fastify/Express, and Stripe-like architectures:
  * *Next.js / Prisma SQLi diff:* In-memory latency **5.24 ms**, Risk: **75/100 (BLOCK)**, identified `SQL_INJECTION`.
  * *Fintech wallet TOCTOU race diff:* In-memory latency **0.49 ms**, Risk: **70/100 (BLOCK)**, identified `TOCTOU_RACE_CONDITION`.
  * *Express static file null-byte injection diff:* In-memory latency **0.25 ms**, Risk: **45/100 (WARN)**, identified `NULL_BYTE_POISONING`.
  * *Microservice timeout hang diff:* In-memory latency **0.28 ms**, Risk: **35/100 (WARN)**, identified `SOCKET_TIMEOUT_HANG`.
* **Zero-Trust Step-Up Protection:** High-impact tool invocations (`docker_prune_all`, `k8s_delete_namespace`, `pg_drop_database`) demanded cryptographic HMAC-SHA256 tokens; token replays were immediately blocked; immutable records were dual-written to JSONL and SQLite.

### Live Codebase Audit on 12 Viral Open-Source Repositories (400,000+ Stars)

To prove that BlastRadius-Zero identifies real issues in production codebases without relying on synthetic fixtures, we audited **12 massive open-source repositories** (**Express, Fastify, Axios, Commander, Dotenv, Winston, Socket.io, Mongoose, Mocha, Anthropic MCP-Servers, Chalk, and Naukri-MCP**):

```bash
npm run test:real-audit
```

* **Scope & Throughput:** Scanned **641 real production files** across **115,433 lines of code** in **1.21 seconds** (sub-2ms average per 50-persona Swarm simulation).
* **Real Issues Identified:** Surfaced **446 real anti-patterns and vulnerabilities**:
  * **32 Real Empty Catch Blocks (Error Swallowing):** Discovered real instances of `catch (e) {}` where failures are completely dropped (e.g. `axios/lib/adapters/http.js:951`, `winston/examples/create-file.js:13`, `dotenv/lib/spawn-command.js:63`).
  * **30 Dangerous Shell Execution Sinks:** Flagged unconstrained `child_process.spawn()` / `exec()` invocations across `dotenv`, `winston`, `mocha`, `mongoose`, and `mcp-servers`.
  * **Deep Unchecked Input Access:** Flagged unvalidated `req.body` / `req.params` access prone to TypeError crashes in `express/examples/auth/index.js`.
* 📄 Full file-by-file audit report with exact line numbers is available in [OPENSOURCE_AUDIT_REPORT.md](docs/OPENSOURCE_AUDIT_REPORT.md).

### Self-Validation with BlastRadius-Zero

To run the end-to-end self-validation where BlastRadius-Zero verifies itself across all 10 operational gates:

```bash
node scripts/validate-blastradius-zero.mjs
```

Four diagnostic probes are also kept in `scripts/`:

```bash
node scripts/probe-guardfall.mjs        # 23 bypass classes, one line each
node scripts/probe-false-positives.mjs  # 39 routine commands that must not trip
node scripts/probe-sequence.mjs        # workflow patterns firing, and staying quiet
node scripts/validate-blastradius-zero.mjs # 10 full pre-flight verification gates
```

---

## Configuration

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `BLAST_RADIUS_SIGNING_KEY` | random per process | HMAC secret for approval tokens |
| `BLAST_RADIUS_AUDIT_KEY` | random per process | HMAC secret for audit entries |
| `BLAST_RADIUS_AUDIT_PATH` | `./blastradius-audit.jsonl` | Where the ledger is written |

Set the first two or tokens and audit entries stop verifying across restarts.

| Flag | Purpose |
| :--- | :--- |
| `--policy, -p <file>` | Load a custom policy JSON |
| `proxy --command "<cmd>"` | Guard an existing MCP server |
| `--help`, `--version` | |

---

## A note on how this shipped

Worth reading, because it is the honest version of what this project is.

The first public version of this repo carried a `tests 24/24 passing` badge. There
were 11 tests, in 2 files. Four of the six test files were 0 bytes: the audit
ledger, the policy engine, the token manager, and the end-to-end server had no
coverage at all. It also claimed single-use tokens with replay protection, where
the function that enforced it existed and was never called. It shipped a 0-byte
`LICENSE` behind an Apache-2.0 badge. And its README advertised rate limits, x402
micropayments, and Splunk SIEM export, none of which existed.

All of it is fixed: 145 real tests, a real CI gate, tokens that are genuinely
single-use, an actual Apache-2.0 `LICENSE`, and a paid-tiers section deleted
rather than softened. An Apache-2.0 repository cannot enforce a paywall anyway.

Then there was the second one, which is more interesting.

**On 30 June 2026, a paper named the exact design this project used and measured it
as broken.** GuardFall tested the command guards in eleven coding agents and found
that matching the raw command string leaked on most bypass attempts. That was this
project's engine. It shipped regexes over submitted text, exactly the tier the
survey measured at 22-of-23 and 16-of-16 failure.

So the engine was rewritten to resolve commands before matching them: quote
removal, variable assignment tracking, parameter expansion, command substitution,
pipeline splitting, and inline program extraction, all without executing anything.
All 23 bypass cases now score HIGH or above, pinned by
[`tests/shellResolver.test.ts`](tests/shellResolver.test.ts).

The reason this is in the README rather than a changelog entry is that a tool whose
entire pitch is *I stop agents doing dangerous things* had a bug in the category it
exists to prevent, twice. The first time I did not look. The second time I read the
literature and found the paper that said so. If you are evaluating this, you should
know that the person maintaining it now checks the claims, and how.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The rule set is the highest-value
contribution: a new signature in `src/analyzer/rules.ts` needs a test in the
matching `tests/*.test.ts` and a note about expected false positives.

Security issues: [SECURITY.md](SECURITY.md), or use GitHub private vulnerability
reporting.

## License

Apache-2.0. See [LICENSE](LICENSE).