import test from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  StdioClientTransport,
  getDefaultEnvironment
} from '@modelcontextprotocol/sdk/client/stdio.js';

const E2E_TIMEOUT = { timeout: 30000 };
const SERVER_ENTRY = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'src',
  'index.js'
);
const EXPECTED_TOOLS = [
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
];


interface ToolTextContent {
  type?: string;
  text?: string;
}

interface SimulationResponse {
  status: string;
  simulation: {
    dangerScore: number;
    severity: string;
    destructive: boolean;
    irreversible: boolean;
  };
}

interface DlpResponse {
  status: string;
  dlpReport: {
    hasFindings: boolean;
    findingsCount: number;
    findings: Array<{ type: string; category: string; severity: string }>;
    sanitizedContent: string;
  };
}

interface EnforcePolicyResponse {
  status: string;
  decision: string;
  reasons: string[];
  requiresToken: boolean;
  blastRadius: { dangerScore: number; severity: string; destructive: boolean };
  auditReceipt: { index: number; receiptId: string; signature: string };
}

interface TokenResponse {
  status: string;
  confirmationToken: string;
  details: { tokenId: string; toolName: string; expiresAt: number };
}

interface VerifyAuditResponse {
  status: string;
  verification: { intact: boolean; totalEntries: number; verifiedCount: number };
}

interface PostureResponse {
  status: string;
  edition: string;
  license: string;
  licenseKeyRequired: boolean;
  rateLimited: boolean;
  capabilities: Record<string, boolean>;
  metrics: { totalInvocations: number; blockedCount: number };
  auditLedger: { intact: boolean; recordedEntries: number };
  activePolicy: string;
}

function firstText(result: unknown): string {
  const content = (result as { content?: ToolTextContent[] }).content;
  const text = content?.[0]?.text;
  assert.strictEqual(typeof text, 'string', 'tool result should carry text content');
  return text ?? '';
}

function parseToolJson<T>(result: unknown): T {
  return JSON.parse(firstText(result)) as T;
}

/**
 * Spawns the real stdio server and hands a connected MCP client to `run`. The
 * server writes its audit ledger into process.cwd(), so the spawned process is
 * pinned to a throwaway directory and this process is moved there too. Both the
 * cwd and the temp folder are restored afterwards.
 */
async function withServer<T>(run: (client: Client) => Promise<T>): Promise<T> {
  const originalCwd = process.cwd();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-e2e-'));
  const client = new Client(
    { name: 'blastradius-e2e-client', version: '1.0.0' },
    { capabilities: {} }
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: { ...getDefaultEnvironment(), BLAST_RADIUS_AUDIT_KEY: 'e2e-audit-signing-key' },
    cwd: tmpDir
  });

  process.chdir(tmpDir);
  try {
    await client.connect(transport);
    return await run(client);
  } finally {
    await client.close();
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('BlastRadiusServer - Completes a full JSON-RPC lifecycle over stdio', E2E_TIMEOUT, async () => {
  await withServer(async (client) => {
    const { tools } = await client.listTools();

    assert.deepStrictEqual(
      tools.map((tool) => tool.name).sort(),
      EXPECTED_TOOLS
    );
    for (const tool of tools) {
      assert.ok(
        typeof tool.description === 'string' && tool.description.length > 0,
        `${tool.name} should advertise a description`
      );
      assert.strictEqual(tool.inputSchema.type, 'object', `${tool.name} should declare an object schema`);
    }

    const simulation = parseToolJson<SimulationResponse>(
      await client.callTool({ name: 'simulate_action', arguments: { commandOrQuery: 'rm -rf /' } })
    );

    assert.strictEqual(simulation.status, 'SUCCESS');
    assert.strictEqual(simulation.simulation.severity, 'CRITICAL');
    assert.strictEqual(simulation.simulation.dangerScore, 100);
    assert.strictEqual(simulation.simulation.destructive, true);
    assert.strictEqual(simulation.simulation.irreversible, true);
  });
});

test('BlastRadiusServer - Redacts secrets over the wire and blocks .env access', E2E_TIMEOUT, async () => {
  await withServer(async (client) => {
    const dlpCall = await client.callTool({
      name: 'inspect_payload_dlp',
      arguments: {
        content: 'Deploying now with AWS key AKIAIOSFODNN7EXAMPLE attached.',
        maskSensitive: true
      }
    });

    const dlp = parseToolJson<DlpResponse>(dlpCall);
    assert.strictEqual(dlp.status, 'SUCCESS');
    assert.strictEqual(dlp.dlpReport.hasFindings, true);
    assert.strictEqual(dlp.dlpReport.findings[0].type, 'AWS_ACCESS_KEY');
    assert.ok(dlp.dlpReport.sanitizedContent.includes('[REDACTED_AWS_KEY:'));
    assert.ok(firstText(dlpCall).includes('REDACTED_'));
    assert.ok(!firstText(dlpCall).includes('AKIAIOSFODNN7EXAMPLE'));

    const blocked = parseToolJson<EnforcePolicyResponse>(
      await client.callTool({
        name: 'enforce_policy',
        arguments: {
          toolName: 'write_file',
          parameters: { path: '/srv/app/.env.production', operation: 'write' },
          callerId: 'e2e-client'
        }
      })
    );

    assert.strictEqual(blocked.status, 'BLOCKED');
    assert.strictEqual(blocked.decision, 'BLOCK');
    assert.strictEqual(blocked.requiresToken, false);
    assert.ok(blocked.reasons.some((reason) => reason.includes('Protect Secret & Auth Files')));
    assert.ok(blocked.reasons.some((reason) => reason.includes('protected path')));
    assert.ok(blocked.auditReceipt.receiptId.match(/^[0-9a-f]{64}$/));
  });
});

test('BlastRadiusServer - Reports an open-source edition with no license key or rate limit', E2E_TIMEOUT, async () => {
  await withServer(async (client) => {
    await client.callTool({ name: 'simulate_action', arguments: { commandOrQuery: 'ls' } });

    const posture = parseToolJson<PostureResponse>(
      await client.callTool({ name: 'get_security_posture', arguments: {} })
    );

    assert.strictEqual(posture.edition, 'open-source');
    assert.strictEqual(posture.license, 'Apache-2.0');
    assert.strictEqual(posture.licenseKeyRequired, false);
    assert.strictEqual(posture.rateLimited, false);
    assert.strictEqual(posture.capabilities.singleUseTokens, true);
    assert.strictEqual(posture.capabilities.hashChainedAuditLedger, true);
    assert.strictEqual(posture.activePolicy, 'Default Zero-Trust Shield');
    assert.ok(posture.metrics.totalInvocations >= 1);
    assert.strictEqual('licenseTier' in posture, false);

    const verification = parseToolJson<VerifyAuditResponse>(
      await client.callTool({ name: 'verify_audit_log', arguments: { limit: 10 } })
    );
    assert.strictEqual(verification.status, 'VERIFIED_INTACT');
    assert.strictEqual(verification.verification.intact, true);
  });
});

test('BlastRadiusServer - Accepts a step-up token once and rejects the replay', E2E_TIMEOUT, async () => {
  await withServer(async (client) => {
    const targetTool = 'deploy_production';
    const enforceArgs = {
      toolName: targetTool,
      parameters: { command: 'git push origin main --force' },
      callerId: 'e2e-client'
    };

    const unapproved = parseToolJson<EnforcePolicyResponse>(
      await client.callTool({ name: 'enforce_policy', arguments: enforceArgs })
    );
    assert.strictEqual(unapproved.decision, 'REQUIRE_CONFIRMATION');
    assert.strictEqual(unapproved.requiresToken, true);
    assert.strictEqual(unapproved.blastRadius.severity, 'HIGH');

    const issued = parseToolJson<TokenResponse>(
      await client.callTool({
        name: 'request_confirmation_token',
        arguments: {
          toolName: targetTool,
          actionFingerprint: 'sha256:action-fingerprint',
          requestedBy: 'e2e-supervisor',
          ttlSeconds: 300
        }
      })
    );
    assert.strictEqual(issued.status, 'TOKEN_ISSUED');
    assert.ok(issued.confirmationToken.includes('.'));

    const approved = parseToolJson<EnforcePolicyResponse>(
      await client.callTool({
        name: 'enforce_policy',
        arguments: { ...enforceArgs, confirmationToken: issued.confirmationToken }
      })
    );
    assert.strictEqual(approved.decision, 'ALLOW');
    assert.strictEqual(approved.status, 'PROCEED');

    const replayed = parseToolJson<EnforcePolicyResponse>(
      await client.callTool({
        name: 'enforce_policy',
        arguments: { ...enforceArgs, confirmationToken: issued.confirmationToken }
      })
    );
    assert.strictEqual(replayed.decision, 'REQUIRE_CONFIRMATION');
    assert.strictEqual(replayed.requiresToken, true);
    assert.ok(replayed.reasons.some((reason) => reason.includes('replay')));

    const verification = parseToolJson<VerifyAuditResponse>(
      await client.callTool({ name: 'verify_audit_log', arguments: { limit: 10 } })
    );
    assert.strictEqual(verification.verification.intact, true);
    assert.strictEqual(verification.verification.totalEntries, 3);
  });
});
