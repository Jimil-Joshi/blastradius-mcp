import test, { after, before } from 'node:test';
import assert from 'node:assert';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { BlastRadiusServer } from '../../src/server.js';
import { dataFlywheel } from '../../src/storage/flywheel.js';
import { AuditLedger } from '../../src/security/auditLedger.js';

interface ToolTextContent {
  type?: string;
  text?: string;
}

function firstText(result: unknown): string {
  const content = (result as { content?: ToolTextContent[] }).content;
  const text = content?.[0]?.text;
  assert.strictEqual(typeof text, 'string', 'Tool call must return a text content item');
  return text ?? '';
}

function parseJson<T = any>(result: unknown): T {
  return JSON.parse(firstText(result)) as T;
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-server12-'));
const ledgerFile = path.join(tmpDir, 'blastradius-audit.jsonl');

before(() => {
  AuditLedger.initialize(ledgerFile);
});

after(() => {
  AuditLedger.reset();
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}
});

async function createServerClientPair() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = new BlastRadiusServer();
  await server.connect(serverTransport);

  const client = new Client(
    { name: 'integration-test-client', version: '2.0.0' },
    { capabilities: {} }
  );
  await client.connect(clientTransport);

  return {
    server,
    client,
    async cleanup() {
      await client.close();
      await server.close();
    }
  };
}

const EXPECTED_12_TOOLS = [
  'adversarial_persona_review',
  'automated_code_critique',
  'blast_radius_heatmap',
  'enforce_tdd_state',
  'generate_socratic_spec',
  'get_security_posture',
  'request_confirmation_token',
  'route_tool',
  'simulate_swarm_impact',
  'spawn_worktree_subagent',
  'verify_audit_log',
  'virtualize_context'
].sort();

test('BlastRadius-Zero Server - tools/list advertises all 12 tools with valid schemas', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const { tools } = await client.listTools();

    assert.strictEqual(tools.length, 12, 'Must list exactly 12 tools');

    const listedNames = tools.map((t) => t.name).sort();
    assert.deepStrictEqual(listedNames, EXPECTED_12_TOOLS, 'Tool names must match expected 12 tools');

    for (const tool of tools) {
      assert.ok(
        typeof tool.description === 'string' && tool.description.trim().length > 0,
        `Tool ${tool.name} must declare a non-empty description`
      );
      assert.strictEqual(
        tool.inputSchema.type,
        'object',
        `Tool ${tool.name} must declare an object inputSchema`
      );
      assert.ok(
        typeof tool.inputSchema.properties === 'object',
        `Tool ${tool.name} must declare properties in its inputSchema`
      );
    }
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 1: route_tool resolves intent to downstream tool', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'route_tool',
      arguments: {
        intent: 'query user records from postgres'
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.ok(parsed.routeResult, 'routeResult must be present');
    assert.strictEqual(typeof parsed.routeResult.matchedTool, 'string');
    assert.ok(parsed.routeResult.confidence > 0, 'confidence must be > 0');
    assert.ok(parsed.routeResult.tokensSaved >= 0, 'tokensSaved must be non-negative');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 2: virtualize_context compresses raw content into handle', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const largeContent = 'Log entry item with detailed stack trace and execution context\n'.repeat(60);
    const rawResult = await client.callTool({
      name: 'virtualize_context',
      arguments: {
        rawContent: largeContent,
        label: 'server-logs',
        retentionTtlSeconds: 1800
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.ok(parsed.handle, 'Virtual handle must be returned');
    assert.ok(parsed.handle.handleId.startsWith('ctx_'), 'handleId must have ctx_ prefix');
    assert.ok(parsed.handle.tokensSaved > 0, 'Tokens saved must be > 0');
    assert.ok(parsed.handle.tokenReductionPercentage >= 80, 'Token reduction should exceed 80%');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 3: simulate_swarm_impact stress-tests diff and records telemetry', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const authDiff = `
      function refreshSession(token) {
        const decoded = jwt.decode(token);
        db.query("SELECT * FROM sessions WHERE user_id = '" + decoded.sub + "'");
        return generateNewToken(decoded.sub);
      }
    `;

    const rawResult = await client.callTool({
      name: 'simulate_swarm_impact',
      arguments: {
        targetDiffOrCommand: authDiff,
        contextDescription: 'Auth token refresh and session query update',
        agentCount: 25,
        intensity: 'FAST'
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.ok(parsed.simulationId, 'simulationId must be generated');
    assert.ok(['SAFE', 'WARN', 'BLOCK'].includes(parsed.verdict), 'Verdict must be SAFE, WARN, or BLOCK');
    assert.ok(typeof parsed.prRiskScore === 'number' && parsed.prRiskScore >= 0 && parsed.prRiskScore <= 100);
    assert.ok(Array.isArray(parsed.findings), 'Findings must be an array');
    assert.ok(typeof parsed.heatmap === 'string' && parsed.heatmap.length > 0, 'Heatmap must be rendered');

    // Telemetry: Verify DataFlywheel has recorded simulations
    const flywheelStats = dataFlywheel.getStats();
    assert.ok(flywheelStats.totalSimulations >= 1, 'DataFlywheel must record simulation run');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 4: adversarial_persona_review runs targeted persona review with reproduction steps', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'adversarial_persona_review',
      arguments: {
        targetDiffOrCommand: "async function getUser(id) { return await db.query(`SELECT * FROM users WHERE id = '${id}'`); }",
        personaType: 'HACKER',
        depth: 2
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.strictEqual(parsed.personaType, 'HACKER');
    assert.strictEqual(parsed.depth, 2);
    assert.ok(Array.isArray(parsed.findings), 'Findings must be an array');
    assert.ok(parsed.findings.length > 0, 'Hacker persona must detect SQL injection in raw concatenation');

    const firstFinding = parsed.findings[0];
    assert.ok(firstFinding.attackVector, 'Finding must have attackVector');
    assert.ok(Array.isArray(firstFinding.reproductionSteps), 'Finding must have reproductionSteps');
    assert.ok(firstFinding.reproductionSteps.length > 0, 'Reproduction steps must not be empty');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 5: blast_radius_heatmap returns rendered matrix in requested format', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const diff = 'function verifyPermissions(user) { if (user.admin) return true; return false; }';

    const rawResult = await client.callTool({
      name: 'blast_radius_heatmap',
      arguments: {
        targetDiffOrCommand: diff,
        format: 'MARKDOWN'
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.strictEqual(parsed.format, 'MARKDOWN');
    assert.ok(typeof parsed.overallScore === 'number');
    assert.ok(typeof parsed.heatmap === 'string');
    assert.ok(parsed.heatmap.includes('Blast Heatmap') || parsed.heatmap.includes('Component'));
    assert.ok(parsed.matrix && Array.isArray(parsed.matrix.cells));
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 6: enforce_tdd_state transitions Red -> Green state lifecycle', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const featureName = 'jwt-refresh-rotation';

    // 1. Register failing test (RED_PENDING)
    const redResult = await client.callTool({
      name: 'enforce_tdd_state',
      arguments: {
        featureName,
        action: 'REGISTER_FAILING_TEST',
        testFilePath: 'tests/jwt.test.ts',
        testOutput: 'AssertionError: expected null to equal valid_token'
      }
    });
    const parsedRed = parseJson(redResult);
    assert.strictEqual(parsedRed.status, 'SUCCESS');
    assert.strictEqual(parsedRed.state.phase, 'RED_PENDING');
    assert.strictEqual(parsedRed.state.failingTestPath, 'tests/jwt.test.ts');

    // 2. Query state (GET_STATE)
    const stateResult = await client.callTool({
      name: 'enforce_tdd_state',
      arguments: {
        featureName,
        action: 'GET_STATE'
      }
    });
    const parsedState = parseJson(stateResult);
    assert.strictEqual(parsedState.status, 'SUCCESS');
    assert.strictEqual(parsedState.state.activeFeature, featureName);
    assert.strictEqual(parsedState.state.phase, 'RED_PENDING');

    // 3. Reset state
    const resetResult = await client.callTool({
      name: 'enforce_tdd_state',
      arguments: {
        featureName,
        action: 'RESET'
      }
    });
    const parsedReset = parseJson(resetResult);
    assert.strictEqual(parsedReset.status, 'SUCCESS');
    assert.strictEqual(parsedReset.state.phase, 'IDLE');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 7: generate_socratic_spec decomposes requirements into contracts', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'generate_socratic_spec',
      arguments: {
        featureRequirement: 'Add JWT token refresh endpoint with replay detection',
        targetComponents: ['Auth', 'Gateway'],
        depth: 'DETAILED'
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.ok(parsed.spec, 'Specification must be generated');
    assert.ok(parsed.spec.featureName, 'Feature name must be derived');
    assert.ok(Array.isArray(parsed.spec.invariants) && parsed.spec.invariants.length > 0);
    assert.ok(Array.isArray(parsed.spec.edgeCases) && parsed.spec.edgeCases.length > 0);
    assert.ok(Array.isArray(parsed.spec.testPlan) && parsed.spec.testPlan.length > 0);
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 8: spawn_worktree_subagent handles subagent workspace isolation', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'spawn_worktree_subagent',
      arguments: {
        agentId: 'test-agent',
        branchName: 'feat/subagent-test',
        baseBranch: 'HEAD'
      }
    });

    const parsed = parseJson(rawResult);
    assert.ok(['CREATED', 'FALLBACK_FOLDER'].includes(parsed.status));
    assert.ok(parsed.worktree, 'Worktree result must be returned');
    assert.strictEqual(parsed.worktree.agentId, 'test-agent');
    assert.ok(typeof parsed.worktree.worktreePath === 'string');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 9: automated_code_critique identifies anti-patterns', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const flawedCode = `
      function loadUserData(req) {
        try {
          exec(req.query.cmd);
        } catch (e) {
          // silently ignored
        }
      }
    `;

    const rawResult = await client.callTool({
      name: 'automated_code_critique',
      arguments: {
        diffOrCode: flawedCode,
        filePath: 'src/handler.ts',
        strictSecurity: true
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'SUCCESS');
    assert.ok(parsed.critique, 'Critique report must be returned');
    assert.ok(typeof parsed.critique.score === 'number');
    assert.ok(parsed.critique.score < 100, 'Flawed code must score below 100');
    assert.ok(parsed.critique.findings.length > 0, 'Critique must flag anti-patterns');
    assert.ok(
      parsed.critique.findings.some((f: any) => f.ruleId === 'EMPTY_CATCH_BLOCK' || f.ruleId === 'DANGEROUS_SHELL_SINK')
    );
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 10: verify_audit_log cryptographically verifies ledger', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'verify_audit_log',
      arguments: {
        limit: 10
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'VERIFIED_INTACT');
    assert.ok(parsed.verification, 'Verification payload must be returned');
    assert.strictEqual(parsed.verification.intact, true);
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 11: request_confirmation_token issues signed tokens', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'request_confirmation_token',
      arguments: {
        toolName: 'bash',
        actionFingerprint: 'abc',
        requestedBy: 'dev',
        ttlSeconds: 300,
        reason: 'Authorized DB migration'
      }
    });

    const parsed = parseJson(rawResult);
    assert.strictEqual(parsed.status, 'TOKEN_ISSUED');
    assert.ok(typeof parsed.confirmationToken === 'string' && parsed.confirmationToken.length > 0);
    assert.strictEqual(parsed.details.toolName, 'bash');
    assert.strictEqual(parsed.details.actionFingerprint, 'abc');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Tool 12: get_security_posture computes real-time security posture', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    const rawResult = await client.callTool({
      name: 'get_security_posture',
      arguments: {
        includeHistory: false
      }
    });

    const parsed = parseJson(rawResult);
    assert.ok(typeof parsed.overallScore === 'number');
    assert.ok(['ACTIVE', 'WARNING', 'ALERT'].includes(parsed.status));
    assert.ok(parsed.metrics, 'Metrics must be reported');
    assert.ok(parsed.auditChain, 'Audit chain status must be reported');
  } finally {
    await cleanup();
  }
});

test('BlastRadius-Zero Server - Maintains legacy tool support and dual-writes telemetry', async () => {
  const { client, cleanup } = await createServerClientPair();
  try {
    // 1. Legacy simulate_action
    const simResult = await client.callTool({
      name: 'simulate_action',
      arguments: { commandOrQuery: 'rm -rf /' }
    });
    const parsedSim = parseJson(simResult);
    assert.strictEqual(parsedSim.status, 'SUCCESS');
    assert.strictEqual(parsedSim.simulation.severity, 'CRITICAL');

    // 2. Legacy inspect_payload_dlp
    const dlpResult = await client.callTool({
      name: 'inspect_payload_dlp',
      arguments: {
        content: 'Configured AWS with AKIAIOSFODNN7EXAMPLE for deployment',
        maskSensitive: true
      }
    });
    const parsedDlp = parseJson(dlpResult);
    assert.strictEqual(parsedDlp.status, 'SUCCESS');
    assert.strictEqual(parsedDlp.dlpReport.hasFindings, true);

    // 3. Legacy enforce_policy with dual-write to AuditLedger and DataFlywheel
    const enforceResult = await client.callTool({
      name: 'enforce_policy',
      arguments: {
        toolName: 'read_file',
        parameters: { path: '/tmp/safe.txt' },
        callerId: 'test-agent'
      }
    });
    const parsedEnforce = parseJson(enforceResult);
    assert.strictEqual(parsedEnforce.status, 'PROCEED');
    assert.ok(parsedEnforce.auditReceipt.receiptId, 'Audit receipt must carry hash');

    // Verify dual-write: AuditLedger and DataFlywheel
    const auditVerification = AuditLedger.verifyIntegrity(10);
    assert.strictEqual(auditVerification.intact, true);
    assert.ok(auditVerification.totalEntries >= 1);
  } finally {
    await cleanup();
  }
});
