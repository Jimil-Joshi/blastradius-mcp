# BlastRadius-Zero v2.0 — Architecture & Implementation Plan
## The Pre-Flight Safety & Zero-Bloat Gateway Runtime for AI Agents

---

## 1. Executive Summary & Vision

### 1.1 The Breakthrough Discovery
The MiroFish ecosystem simulation (64 nodes, 80 edges, 25 personas across 120 rounds) revealed a fundamental shift in market demand:
Developers and enterprises do **not** want three fragmented tools ("Superpowers + MiroFish + ContextKernel"). 
Instead, they demand a **single unified runtime primitive**: **BlastRadius-Zero (Pre-Flight Safety + Zero-Bloat Gateway)**.

### 1.2 The Psychological Trigger & Viral Demo
> *"I asked my agent to refactor auth. It wrote code, then simulated 50 users attacking it, found a race condition, wrote the test, fixed it, and merged. All while I drank coffee."*

This visceral 30-second workflow creates the viral loop:
1. **Safety First**: Before any code or command executes against production or PRs, simulated adversarial personas stress-test it in seconds.
2. **Zero-Bloat Routing**: 100+ MCP tools can be connected without blowing LLM context budgets or paying the "MCP Tax".
3. **Ironclad Quality**: Enforces strict TDD (Red -> Green -> Refactor) and isolated Git worktrees.
4. **Defensible Data Flywheel**: Every simulation run generates attack telemetry that compounds into local rules and custom personas.

---

## 2. High-Level Architecture

BlastRadius-Zero operates as a **single, unified MCP server** built on Node.js 24+ and TypeScript with strict typing, zero external runtime bloat, and full backward compatibility with the existing 145 passing tests.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        BLASTRADIUS-ZERO MCP SERVER (v2.0.0)                            │
├──────────────────────────┬──────────────────────────┬──────────────────────────────────┤
│   ZERO-BLOAT GATEWAY     │     SWARM PRE-FLIGHT     │           TDD ENFORCER           │
│    (Context Router)      │    (Safety Simulator)    │          (Quality Gate)          │
├──────────────────────────┼──────────────────────────┼──────────────────────────────────┤
│ • 1 semantic router      │ • simulate_swarm_impact  │ • enforce_tdd_state (Red/Green)  │
│   replaces 50 schemas    │   (fast 2-5 sec engine)  │ • generate_socratic_spec         │
│ • JIT schema fetch       │ • adversarial_persona_   │ • spawn_worktree_subagent        │
│ • Local sandbox executor │   review (50 personas)   │ • automated_code_critique        │
│ • virtualize_context     │ • blast_radius_heatmap   │ • refactor_green validator       │
│ • 85% token reduction    │ • PR risk score 0-100    │                                  │
├──────────────────────────┴──────────────────────────┴──────────────────────────────────┤
│                       ZERO-TRUST COMPLIANCE & RE-INFORCEMENT                           │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ • verify_audit_log (HMAC-SHA256 tamper-evident ledger)                                │
│ • request_confirmation_token (step-up approval tokens with crypto signatures)          │
│ • get_security_posture (real-time risk, TDD state, and self-enhancement flywheel)      │
│ • Persistent Data Flywheel: SQLite (node:sqlite) + Hash-Chained JSONL                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 12 MCP Tools Specification

BlastRadius-Zero exposes exactly **12 high-impact MCP tools** designed for viral adoption, developer safety, and enterprise compliance.

| # | Tool Name | Pillar | Purpose & Viral Demo Hook |
|---|---|---|---|
| 1 | `route_tool` | Gateway | *"Use 100 MCP servers, pay for 1 token"* — Semantic JIT router |
| 2 | `virtualize_context` | Gateway | *"Infinite agent context"* — Compress large payloads & session histories |
| 3 | `simulate_swarm_impact` | Safety | ⭐ **THE DEMO** — *"Watch 50 personas attack my PR in 3 seconds"* |
| 4 | `adversarial_persona_review` | Safety | Run targeted red-team audits with hacker, confused user & legacy system |
| 5 | `blast_radius_heatmap` | Safety | Visual ASCII / Markdown matrix of services, users, and DB tables at risk |
| 6 | `enforce_tdd_state` | Quality | *"Agent cannot touch prod code until tests fail"* — Enforce Red/Green/Refactor |
| 7 | `generate_socratic_spec` | Quality | *"Specs so clear a junior could build it"* — Socratic requirement decomposition |
| 8 | `spawn_worktree_subagent` | Quality | *"Parallel agents, zero dirty files"* — Isolated Git worktree execution |
| 9 | `automated_code_critique` | Quality | *"Senior dev review on every commit"* — AST & security anti-pattern critique |
| 10 | `verify_audit_log` | Compliance | Tamper-proof cryptographic audit chain for SOC2 / ISO 27001 |
| 11 | `request_confirmation_token`| Compliance | Cryptographic step-up token for high-risk operations |
| 12 | `get_security_posture` | Compliance | Real-time risk posture (0-100), TDD status, and flywheel learning stats |

> **Backward Compatibility Note:** Existing foundational primitives (`simulate_action`, `inspect_payload_dlp`, `enforce_policy`) remain fully supported internally and available for backward-compatible proxy pipelines.

---

## 4. Subsystems Deep Dive

### 4.1 Subsystem 1: Zero-Bloat Gateway (`src/gateway/`)

#### Problem
Registering dozens of MCP servers bloats agent context windows by 20,000–50,000 tokens per prompt ("MCP Tax"), degrading agent reasoning and multiplying API costs.

#### Solution
1. **Semantic & Keyword Intent Router (`route_tool`)**:
   - Only 1 router schema is exposed in the LLM's system prompt.
   - When the agent intends to take an action, it provides the natural-language intent or target tool name.
   - The router queries a local index of downstream tools, selects the best match with similarity/confidence scoring, and JIT-fetches only the target tool's exact schema.
   - In proxy mode, it executes the target tool inside the BlastRadius security sandbox (running DLP and command resolution before dispatch).
2. **Context Virtualizer (`virtualize_context`)**:
   - Takes large tool outputs (logs, big diffs, multi-megabyte JSON responses) and writes them to local temporary storage.
   - Returns a structured virtual handle with token savings, key metadata, preview snippets, and query handles.
   - Cuts context token consumption by 85–95%.

```typescript
// src/gateway/types.ts
export interface RouteToolParams {
  intent: string;                  // e.g. "deploy commit to staging" or "query active sessions"
  candidateServer?: string;        // optional hint e.g. "postgres", "github"
  executeImmediately?: boolean;    // if true, execute if risk score is SAFE/LOW
  toolArguments?: Record<string, any>;
}

export interface VirtualizeContextParams {
  rawContent: string;              // content to virtualize
  label: string;                   // human-readable label
  retentionTtlSeconds?: number;    // default 3600
}
```

---

### 4.2 Subsystem 2: Swarm Pre-Flight Safety Simulator (`src/swarm/`)

#### Problem
Traditional static analyzers miss emergent bugs, race conditions, distributed cascades, and multi-step bypasses. Meanwhile, full external simulation runs take 10+ minutes and require external social network setups.

#### Solution: Dual-Engine Swarm Simulator
BlastRadius-Zero ships with a **hybrid architecture**:

1. **Native Fast In-Memory Engine (Default, 2–5 Seconds)**:
   - Written in pure TypeScript with zero external network or Python dependencies.
   - Spawns 10 to 50 lightweight virtual agent personas:
     - **Security Hacker**: Attacks auth, explores IDOR, injection, privilege escalation, parameter tampering.
     - **Confused User**: Sends malformed payloads, out-of-order calls, boundary violations, rapid re-clicks.
     - **Legacy System**: Stale HTTP headers, deprecated schemas, slow timeouts, network jitter.
     - **Concurrency Attacker**: Simulates simultaneous state mutations, race conditions, locking deadlocks.
     - **Data Corruptor**: Injects special characters, SQL fragments, null bytes, payload boundary overflows.
   - Executes multi-round adversarial micro-turns against the proposed code/action diff.
   - Outputs:
     - **PR Risk Score (0–100)**
     - Identified Attack Vectors & Race Conditions
     - Concrete reproduction steps and unit test assertions.

2. **Visual Blast Radius Heatmap Generator (`blast_radius_heatmap`)**:
   - Generates an instant visual ASCII / Markdown heatmap displaying:
     - Component Blast Radius (Auth, Payment, DB, Cache, Worker)
     - Impacted User Classes (Admin, Staff, Customer, Public)
     - Data Sensitivity Exposure (Critical Secrets, PII, Internal, Public)
     - Containment Feasibility (Rollback ease, compensation actions)

3. **Deep OASIS Bridge Mode (Optional/Hybrid)**:
   - Connects to the local Python OASIS engine at `C:\Users\Jim-per\MiroFish` when deep macro-simulation is explicitly requested (`deepAnalysis: true`).

```typescript
// src/swarm/types.ts
export interface SwarmSimulationRequest {
  targetDiffOrCommand: string;
  contextDescription: string;
  agentCount?: number;             // default: 25, max: 50
  intensity?: 'FAST' | 'DEEP';     // FAST: 2-5 sec native; DEEP: OASIS bridge
  focusAreas?: Array<'SECURITY' | 'CONCURRENCY' | 'USABILITY' | 'DATA_INTEGRITY'>;
}

export interface SwarmSimulationResult {
  simulationId: string;
  prRiskScore: number;             // 0 to 100
  verdict: 'SAFE' | 'WARN' | 'BLOCK';
  personasSimulated: number;
  criticalFindings: Array<{
    personaType: string;
    attackVector: string;
    description: string;
    suggestedTest: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }>;
  heatmapAscii: string;
  divergenceFromStatic: number;
}
```

---

### 4.3 Subsystem 3: TDD Enforcer & Superpowers Quality Gate (`src/quality/`)

#### Problem
Coding agents frequently jump straight into writing implementation code, hallucinating functionality, skipping tests, or claiming "tests passed" without actually running them.

#### Solution
1. **TDD State Machine (`enforce_tdd_state`)**:
   - Tracks session state: `IDLE` -> `RED_PENDING` -> `RED_CONFIRMED` -> `GREEN_PENDING` -> `REFACTOR`.
   - Prevents modifications to production/source files while in `RED_PENDING` (must write a failing test first).
   - Validates that the test actually failed before advancing to `GREEN_PENDING`.
   - Verifies all tests pass before permitting commit/merge in `REFACTOR` state.
2. **Socratic Spec Generator (`generate_socratic_spec`)**:
   - Takes informal feature requests and expands them into rigorous, testable engineering specs:
     - Invariants & Pre-conditions
     - Edge Cases (empty sets, concurrency, Unicode, boundary values)
     - Security & DLP requirements
     - Explicit verification test suite outline.
3. **Worktree Subagent Isolator (`spawn_worktree_subagent`)**:
   - Automates `git worktree` isolation.
   - Spawns parallel branch worktrees in `.blastradius/worktrees/<agent-id>`.
   - Guarantees subagents test and experiment without polluting the primary workspace or breaking active work.
4. **Automated Code Critique (`automated_code_critique`)**:
   - Senior-developer heuristic and AST inspection on changed files:
     - Catches silent error swallowing (`catch (e) {}`), unbounded queries, missing auth checks, unhandled nullables, and unclosed streams.

```typescript
// src/quality/types.ts
export enum TddPhase {
  SPECIFICATION = 'SPECIFICATION',
  RED = 'RED',
  GREEN = 'GREEN',
  REFACTOR = 'REFACTOR'
}

export interface TddStateContext {
  activeFeature: string;
  phase: TddPhase;
  failingTestPath?: string;
  failingTestAssertion?: string;
  greenVerificationTimestamp?: string;
  allowedWritePaths: string[];
}
```

---

### 4.4 Subsystem 4: Compliance & Self-Enhancement Flywheel (`src/compliance/` & `src/storage/`)

#### 1. Tamper-Evident Hash Chain
- Every invocation, simulation finding, router dispatch, and approval token is recorded in an HMAC-SHA256 append-only ledger (`AuditLedger`).
- `verify_audit_log` cryptographically proves log integrity for SOC2/ISO 27001 readiness.

#### 2. Self-Enhancement Data Flywheel (`src/storage/flywheel.ts`)
- Built using Node 24's native `node:sqlite`.
- Stores every simulation failure, persona attack vector, and divergence between static and swarm scoring.
- Automatically generates suggested rules for `rules/custom-rules.json`.
- Compounding advantage: Every test and simulation run enriches the local intelligence database.

---

## 5. File Manifest & Directory Layout

```
blastradius-mcp/
├── src/
│   ├── index.ts                      — Entry point & CLI binary
│   ├── server.ts                     — MCP Server registering the 12 tools
│   ├── types.ts                      — Core types, schemas & enums
│   │
│   ├── gateway/                      — [PILLAR 1: ZERO-BLOAT GATEWAY]
│   │   ├── types.ts                  — Gateway schemas & interfaces
│   │   ├── semanticRouter.ts         — JIT tool router & indexer
│   │   ├── contextVirtualizer.ts     — Payload compression & handles
│   │   └── sandboxExecutor.ts        — Isolated tool dispatcher
│   │
│   ├── swarm/                        — [PILLAR 2: SWARM PRE-FLIGHT]
│   │   ├── types.ts                  — Swarm & persona type definitions
│   │   ├── nativeEngine.ts           — Fast (2-5s) in-memory adversarial engine
│   │   ├── personas/                 — Built-in persona profiles
│   │   │   ├── hackerPersona.ts      — Security, IDOR, SQLi, Auth bypass
│   │   │   ├── confusedUser.ts       — Malformed input, order inversion
│   │   │   ├── legacySystem.ts       — Stale headers, cache desync
│   │   │   └── concurrencyRacer.ts   — Race conditions & deadlocks
│   │   ├── heatmapGenerator.ts       — Visual ASCII / Markdown blast radius matrix
│   │   └── oasisBridge.ts            — Optional deep bridge to Python OASIS
│   │
│   ├── quality/                      — [PILLAR 3: TDD ENFORCER]
│   │   ├── types.ts                  — TDD phases & spec types
│   │   ├── tddStateMachine.ts        — Red -> Green -> Refactor enforcer
│   │   ├── socraticSpec.ts           — Spec generator & boundary extractor
│   │   ├── worktreeManager.ts        — Git worktree isolator for subagents
│   │   └── codeCritique.ts           — Senior dev static & AST critique
│   │
│   ├── analyzer/                     — [EXISTING CORE ENGINES - 100% PRESERVED]
│   │   ├── blastRadiusEngine.ts      — Shell-aware command resolution
│   │   ├── shellResolver.ts          — Bash expansion & AST parser
│   │   ├── rules.ts                  — 21 static detection signatures
│   │   ├── dlpScanner.ts             — 11 credential & PII detectors
│   │   └── sequenceDetector.ts       — Multi-step workflow detector
│   │
│   ├── security/                     — [PILLAR 4: COMPLIANCE]
│   │   ├── auditLedger.ts            — HMAC-SHA256 hash-chained ledger
│   │   ├── tokenManager.ts           — Single-use step-up approval tokens
│   │   └── edition.ts                — Open-source metadata
│   │
│   ├── storage/                      — [DATA FLYWHEEL]
│   │   ├── flywheel.ts               — Node:sqlite storage for attacks & rules
│   │   └── customRulesManager.ts     — Dynamic custom rules persistence
│   │
│   └── tools/                        — [TOOL IMPLEMENTATION HANDLERS]
│       ├── routeToolHandler.ts
│       ├── virtualizeContextHandler.ts
│       ├── simulateSwarmHandler.ts
│       ├── personaReviewHandler.ts
│       ├── heatmapHandler.ts
│       ├── tddStateHandler.ts
│       ├── socraticSpecHandler.ts
│       ├── worktreeSubagentHandler.ts
│       ├── codeCritiqueHandler.ts
│       ├── auditLogHandler.ts
│       ├── tokenHandler.ts
│       └── postureHandler.ts
│
├── tests/
│   ├── analyzer/                     — Existing 145 passing tests (preserved)
│   ├── gateway/                      — Router & virtualizer tests
│   ├── swarm/                        — Fast swarm & heatmap tests
│   ├── quality/                      — TDD state machine & critique tests
│   └── integration/                  — End-to-end 12-tool verification
```

---

## 6. Detailed 7-Day Implementation Roadmap

### Day 1: Swarm Pre-Flight Engine & Visual Heatmap
- **Target**: Implement `src/swarm/nativeEngine.ts`, `src/swarm/personas/`, and `src/swarm/heatmapGenerator.ts`.
- **Tools Activated**:
  - `simulate_swarm_impact`: Runs 25–50 personas against diffs in <3 seconds.
  - `adversarial_persona_review`: Deep dive into specific persona attack logs.
  - `blast_radius_heatmap`: Renders visual ASCII/Markdown heatmaps.
- **Verification**: Fast unit tests confirming sub-3s run time and detection of race condition / auth bypass fixtures.

### Day 2: TDD Enforcer & Quality Gate
- **Target**: Implement `src/quality/tddStateMachine.ts`, `socraticSpec.ts`, `worktreeManager.ts`, and `codeCritique.ts`.
- **Tools Activated**:
  - `enforce_tdd_state`: Strict Red/Green state management.
  - `generate_socratic_spec`: Boundary-hardened specifications.
  - `spawn_worktree_subagent`: Git worktree creation and cleanup.
  - `automated_code_critique`: Senior developer heuristic review.
- **Verification**: Test suite verifying that prod edits are blocked until test failures are registered.

### Day 3: Zero-Bloat Gateway & Router
- **Target**: Implement `src/gateway/semanticRouter.ts` and `contextVirtualizer.ts`.
- **Tools Activated**:
  - `route_tool`: JIT schema retrieval and single-token routing.
  - `virtualize_context`: Payload compression and memory handle management.
- **Verification**: Tests validating >85% token reduction and accurate semantic tool dispatch.

### Day 4: Compliance & Data Flywheel Integration
- **Target**: Implement `src/storage/flywheel.ts` with `node:sqlite` and connect all 12 tools to `src/server.ts`.
- **Tools Activated**:
  - `verify_audit_log`
  - `request_confirmation_token`
  - `get_security_posture` (aggregates swarm, TDD, and gateway metrics).
- **Verification**: All 12 tools registered and responsive over stdio JSON-RPC.

### Day 5: Test Suite & Zero-Regression Verification
- **Target**: Run full test battery.
- **Verification**:
  - All 145 original tests in `tests/analyzer/` continue to pass.
  - New test suites for Gateway, Swarm, Quality, and Compliance pass.
  - `npm run test:src` is 100% green.

### Day 6: The 30-Second Viral Demo Script & Assets
- **Target**: Polish the viral demo recording:
  - Agent receives instruction: "Refactor auth middleware to use JWT refresh tokens".
  - Agent generates Socratic spec and enforces TDD state (`enforce_tdd_state`).
  - Agent calls `simulate_swarm_impact`: 50 personas attack the PR in 3 seconds.
  - Swarm detects race condition (concurrent token refresh replay).
  - Agent shows `blast_radius_heatmap`.
  - Agent writes the reproduction test, fixes the race condition, verifies green, and merges.
- Create GIF / terminal SVG recording for README.

### Day 7: Packaging & Ecosystem Distribution
- **Target**:
  - Update `manifest.json`, `package.json` (version 2.0.0), and `README.md`.
  - Package binary: `npx @blastradius/zero` or `npx blastradius-mcp`.
  - Submit listings to Smithery.ai, Glama.ai, and the official MCP Registry.

---

## 7. Success Criteria & Verification Checklist

Before releasing v2.0.0, the build must satisfy:

1. [ ] **100% Backward Compatibility**: All 145 existing tests pass without errors.
2. [ ] **12 MCP Tools Live**: Complete JSON-RPC tool listing includes all 12 tools.
3. [ ] **Sub-3s Swarm Run**: `simulate_swarm_impact` runs 25+ personas in under 3 seconds locally.
4. [ ] **Visual Heatmap**: `blast_radius_heatmap` outputs a clean, legible markdown/ASCII matrix.
5. [ ] **Zero-Bloat Routing**: `route_tool` selects and executes tools with >80% token savings.
6. [ ] **TDD Strictness**: `enforce_tdd_state` reliably halts code edits during the RED phase.
7. [ ] **Zero-Config Storage**: Flywheel uses built-in `node:sqlite` without external C++ compilation dependencies.
8. [ ] **Tamper-Evident Ledger**: Audit logs maintain cryptographic chain integrity.
