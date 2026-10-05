# 🛡️ BlastRadius MCP — Zero-Trust Security, Blast Radius Simulation & DLP Proxy

[![npm version](https://img.shields.io/npm/v/blastradius-mcp.svg?style=flat-square&color=blue)](https://www.npmjs.com/package/blastradius-mcp)
[![Tests Passing](https://img.shields.io/badge/tests-24%2F24%20passed-brightgreen.svg?style=flat-square)](https://github.com/Jimil-Joshi/blastradius-mcp)
[![Smithery Compatible](https://img.shields.io/badge/Smithery-1--Click%20Ready-orange.svg?style=flat-square)](https://smithery.ai)
[![Glama Verified](https://img.shields.io/badge/Glama-Security%20Scored-purple.svg?style=flat-square)](https://glama.ai)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)

> **The Firewall & Blast-Radius Engine for the Model Context Protocol (MCP).**  
> Protects your infrastructure, cloud environments, and sensitive databases from rogue AI actions, prompt injections, and accidental destruction.

---

## ⚡ The Problem: The AI Agent "Trust Gap"

When you give AI assistants like **Cursor**, **Claude Desktop**, or **autonomous agents** access to bash, filesystem, SQL, or cloud tools, you face catastrophic risks:
1. **Destructive Commands:** An agent can inadvertently run `rm -rf *`, `DROP DATABASE`, or delete production cloud resources.
2. **Credential Leaks & Exfiltration:** Tool inputs and outputs often contain unmasked AWS keys, GitHub tokens, database passwords, or customer PII.
3. **Zero Accountability:** Traditional MCP servers execute commands immediately with no simulation, no rollback mechanism, and no tamper-evident audit trail.

**`BlastRadius` solves this.** It acts as an intelligent pre-execution security proxy and standalone guardrail server for the Model Context Protocol.

---

## 🚀 Key Capabilities

- 💥 **Pre-Execution Blast Radius Simulation:** Analyzes SQL, Shell, Cloud (AWS/GCP/K8s), and Filesystem commands before they execute. Returns danger scores (0–100), estimated blast radius, affected entities, and rollback feasibility.
- 🛡️ **Zero-Trust Policy Enforcement:** Enforces organizational security baselines. Automatically blocks wildcard directory deletion, fork bombs, and modification of `.env` or SSH keys.
- 🔍 **Deep Data Loss Prevention (DLP):** Automatically detects and redacts AWS keys, GitHub PATs, OpenAI/Stripe keys, database passwords, credit cards, SSNs, and emails.
- 🔐 **Cryptographic Step-Up Tokens:** Issues time-bounded, single-use HMAC-SHA256 approval tokens for high-impact actions, ensuring human-in-the-loop authorization with replay protection.
- ⛓️ **Tamper-Evident Hash-Chained Audit Ledger:** Records every tool call into an append-only cryptographic chain. Automatically flags any log alteration, record deletion, or tampering.
- 🔀 **Transparent Reverse-Proxy Mode:** Wraps **ANY existing MCP server** (Postgres, Filesystem, Bash, GitHub) without modifying a single line of downstream code.

---

## 📦 Quickstart in 60 Seconds

### Option A: Use as a Standalone Security Server in Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blastradius": {
      "command": "npx",
      "args": [
        "-y",
        "blastradius-mcp"
      ]
    }
  }
}
```

### Option B: Use in Cursor IDE

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blastradius": {
      "command": "npx",
      "args": [
        "-y",
        "blastradius-mcp"
      ]
    }
  }
}
```

### Option C: Transparent Proxy Mode (Guard Any Existing MCP Server)

Wrap an existing server (e.g., standard filesystem server) with zero-trust guardrails:

```bash
npx blastradius-mcp proxy --command "npx -y @modelcontextprotocol/server-filesystem /workspace"
```

In your AI client config:
```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "blastradius-mcp",
        "proxy",
        "--command",
        "npx -y @modelcontextprotocol/server-filesystem /workspace"
      ]
    }
  }
}
```

---

## 🛠️ Exposed MCP Tools

| Tool Name | Description | Key Arguments |
| :--- | :--- | :--- |
| `simulate_action` | Simulates blast radius, calculates danger score (0-100), severity, and rollback feasibility. | `commandOrQuery`, `actionType`, `context` |
| `inspect_payload_dlp` | Scans text/payload for leaked API keys, credentials, and PII, returning redacted content. | `content`, `maskSensitive` |
| `enforce_policy` | Zero-trust evaluation checking active policy rules and recording to cryptographic ledger. | `toolName`, `parameters`, `confirmationToken` |
| `request_confirmation_token`| Issues an HMAC-SHA256 signed approval token for step-up human authorization. | `toolName`, `actionFingerprint`, `requestedBy`, `ttlSeconds` |
| `verify_audit_log` | Cryptographically verifies the unbroken audit hash chain to detect any log tampering. | `limit` |
| `get_security_posture` | Returns live security metrics, blocked counts, DLP redaction totals, and policy status. | *(none)* |

---

## 🧪 Testing

`BlastRadius` includes an end-to-end test suite verified against Node.js 22+:

```bash
npm run test:src
```

```
✔ AuditLedger - Appends entries with unbroken cryptographic hash chain
✔ AuditLedger - Detects tampering when an audit entry is altered
✔ BlastRadiusEngine - Evaluates rm -rf / as CRITICAL and destructive
✔ BlastRadiusEngine - Evaluates DROP DATABASE as CRITICAL and SQL category
✔ BlastRadiusEngine - Evaluates AWS terminate-instances as CRITICAL
✔ BlastRadiusEngine - Evaluates git push --force as HIGH danger
✔ DLPScanner - Detects AWS Access Keys
✔ DLPScanner - Detects GitHub PAT Tokens
✔ DLPScanner - Detects Database Connection URI Passwords
✔ DLPScanner - Detects Credit Cards and SSNs
✔ PolicyEngine - Hard blocks forbidden pattern rm -rf /
✔ PolicyEngine - Blocks access to protected path .env
✔ PolicyEngine - Requires confirmation token for high severity without token
✔ PolicyEngine - Allows high severity action when valid confirmation token is supplied
✔ BlastRadiusServer E2E - Full JSON-RPC Protocol Lifecycle
✔ TokenManager - Generates and verifies valid token
✔ TokenManager - Prevents replay attacks when token is consumed
...
ℹ tests 24 | pass 24 | fail 0 (455ms)
```

---

## 🏢 Enterprise Licensing & Monetization

- **Community (Free Open Source):** Up to 1,000 tool calls/hr, local audit ledger, built-in Zero-Trust policy.
- **Pro ($49/month):** Custom policy configs, advanced regexes, 50,000 calls/hr, x402 payment header support.
- **Enterprise ($199/seat/month):** Unlimited scale, SIEM export (Splunk/Datadog), multi-node SSO signing keys, SLA guarantee.

Activate via environment variable:
```bash
export BLAST_RADIUS_LICENSE_KEY="ENT-xxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## 📄 License

Apache 2.0. See [LICENSE](LICENSE) for details.
