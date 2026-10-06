# Security Policy

BlastRadius MCP is a security boundary. It sits between an AI agent and the
tools that agent can reach, and it is trusted to make allow/deny decisions. A
bug here is a security bug, so security reports are taken seriously and handled
through private disclosure.

## Reporting a vulnerability

**Do not open a public issue.**

Report it privately via GitHub Security Advisories:

**[Report a vulnerability](https://github.com/Jimil-Joshi/blastradius-mcp/security/advisories/new)**

Use the "Report a vulnerability" button on the Security tab of the repository.
That channel is private between you and the maintainer; it supports encrypted
messages and allows us to work on a fix before anything is public.

Please include:

- Type of issue and the component affected (`src/analyzer`, `src/policy`,
  `src/proxy`, `src/security`, or the token/ledger path).
- The exact input that triggers it — command, SQL, MCP tool call, or payload.
- What you expected versus what happened.
- Impact: what the flaw would let an attacker do.
- Node.js version and `blastradius-mcp` version.

If GitHub advisories are unavailable to you, open a regular issue that says
only "security report available on request" with no technical detail.

## Supported versions

| Version | Supported | Notes |
| :-- | :--: | :-- |
| 1.x | ✅ | Current release line. Patches applied to the latest 1.x. |
| < 1.0 | ❌ | No longer maintained. Upgrade to 1.x. |

## What is in scope

These are the failure modes that matter for this package specifically:

- **DLP detection bypass** — input that should be redacted but is returned in
  cleartext by `inspect_payload_dlp`, or that slips past the outbound redaction
  in proxy mode. Any credential or PII type reachable via an obfuscation that
  the regexes do not handle.
- **Policy bypass** — a command, query, or tool call that `enforce_policy`
  should block (or require confirmation for) but that reaches `ALLOW`.
  Signature evasion for the `SH-`, `SQL-`, `CLD-`, or `FS-` rules counts.
- **Step-up token forgery or replay** — minting or accepting a valid
  `request_confirmation_token` without the signing secret, accepting an expired
  token, using a token across a tool it was not scoped to, or reusing a
  consumed token.
- **Audit-log tampering** — forging, altering, reordering, or deleting entries
  in the JSONL ledger such that `verify_audit_log` still reports the chain as
  intact, or reading the HMAC secret out of process memory or the environment.
- **Command injection in the proxy path** — the `proxy --command "<cmd>"`
  argument reaching a shell with attacker-controlled content, or a downstream
  response being trusted before redaction.
- **Signature verification errors** — `crypto.timingSafeEqual` misuse, a
  truncated or length-mismatched signature being accepted, or a base64url
  decode that silently truncates.
- **Supply-chain issues** — an insecure transitive dependency, or a build step
  that executes untrusted code.

## What is out of scope

- Regex coverage gaps reported as "the tool should detect X" with no bypass of
  a control that claims to exist. Detection is best-effort by design; only
  bypasses are vulnerabilities.
- Denial of service from adversarially large or deeply nested input.
- Findings from automated scanners with no working proof of concept.
- The free COMMUNITY tier's documented rate limits and feature gating.
- Missing detection rules for novel attack patterns. Open an issue instead.
- Vulnerabilities in Claude Desktop, Cursor, the MCP SDK, or other MCP servers
  that blastradius-mcp wraps. Report those upstream.

## Response targets

Best effort, and honestly: this is maintained by one person.

| Severity | Acknowledge | Public fix target |
| :-- | :-- | :-- |
| Critical | 72 hours | 7 days |
| High | 7 days | 14 days |
| Medium | 14 days | Next release |
| Low | 30 days | Next release |

Critical severity means: arbitrary code execution, credential exfiltration, a
complete policy bypass, or forgeable audit records.

If a fix needs longer than the target, you will hear from me with the reason and
a revised date rather than silence.

## Disclosure

- Credit is yours. I will name you in the advisory and the release notes unless
  you ask otherwise.
- Please do not disclose publicly, on social media, or in another issue until a
  fix and a CVE have been issued.
- If a fix is not feasible in reasonable time, a mitigation or a documented
  workaround will be published instead, so you are not left exposed.

## A note on expectations

This is a solo-maintained open-source project. There is no support contract, no
24/7 on-call, and no guaranteed response time — the table above is a genuine
best effort, not an SLA. If you need contractual SLAs, guaranteed response, or
custom signatures, that is the commercial Enterprise tier, not this repository.
