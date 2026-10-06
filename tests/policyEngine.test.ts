import test, { afterEach, beforeEach } from 'node:test';
import assert from 'node:assert';
import { BlastRadiusEngine } from '../src/analyzer/blastRadiusEngine.js';
import { PolicyEngine } from '../src/policy/policyEngine.js';
import { ZERO_TRUST_POLICY } from '../src/policy/defaultPolicies.js';
import { TokenManager } from '../src/security/tokenManager.js';
import {
  BlastRadiusReport,
  PolicyDecision,
  SecurityPolicyConfig,
  SeverityLevel
} from '../src/types.js';

const TOOL_NAME = 'execute_shell';

// Reuses a real engine report for a benign command and only relabels the
// severity, so threshold behaviour can be exercised at bands the shipped rules
// never produce. The base report must stay non-destructive, otherwise the
// zero-trust rule's requireApprovalForDestructive would mask the threshold.
function reportAtSeverity(severity: SeverityLevel): BlastRadiusReport {
  return { ...BlastRadiusEngine.evaluate('npm version minor'), severity };
}

beforeEach(() => {
  TokenManager.resetConsumed();
});

afterEach(() => {
  TokenManager.resetConsumed();
});

test('PolicyEngine - Blocks root and wildcard deletion under rule ZT-001', () => {
  const engine = new PolicyEngine();
  const params = { command: 'rm -rf /' };

  const result = engine.evaluate(TOOL_NAME, params, BlastRadiusEngine.evaluate(params.command));

  assert.strictEqual(result.decision, PolicyDecision.BLOCK);
  assert.strictEqual(result.ruleMatched, 'ZT-001');
  assert.strictEqual(result.requiresToken, false);
  assert.strictEqual(result.tokenValid, undefined);
  assert.ok(result.reasons.some((r) => r.includes('rm -rf /')));
  assert.strictEqual(engine.getPolicy().name, ZERO_TRUST_POLICY.name);
});

test('PolicyEngine - Blocks access to protected secret files under rule ZT-004', () => {
  const engine = new PolicyEngine();
  const params = { path: '/srv/app/.env.production', operation: 'write' };

  const result = engine.evaluate(
    'write_file',
    params,
    BlastRadiusEngine.evaluate(JSON.stringify(params))
  );

  assert.strictEqual(result.decision, PolicyDecision.BLOCK);
  assert.strictEqual(result.ruleMatched, 'ZT-004');
  assert.ok(result.reasons.some((r) => r.includes('protected path')));
});

test('PolicyEngine - Requires a confirmation token for an elevated action when none is supplied', () => {
  const engine = new PolicyEngine();
  const params = { command: 'git push origin main --force' };
  const report = BlastRadiusEngine.evaluate(params.command);
  assert.strictEqual(report.severity, SeverityLevel.HIGH);

  const result = engine.evaluate(TOOL_NAME, params, report);

  assert.strictEqual(result.decision, PolicyDecision.REQUIRE_CONFIRMATION);
  assert.strictEqual(result.ruleMatched, 'ZT-003');
  assert.strictEqual(result.requiresToken, true);
  assert.strictEqual(result.tokenValid, false);
});

test('PolicyEngine - Allows an elevated action once a valid token authorises it and burns it', () => {
  const engine = new PolicyEngine();
  const params = { command: 'git push origin main --force' };
  const report = BlastRadiusEngine.evaluate(params.command);
  const approval = TokenManager.generateToken(
    TOOL_NAME,
    'sha256:action-fingerprint',
    'supervisor@example.com',
    300
  );

  const result = engine.evaluate(TOOL_NAME, params, report, approval.token);

  assert.strictEqual(result.decision, PolicyDecision.ALLOW);
  assert.strictEqual(result.ruleMatched, 'ZT-003');
  assert.strictEqual(result.tokenValid, true);
  assert.strictEqual(result.requiresToken, false);
  assert.strictEqual(TokenManager.isConsumed(approval.payload.tokenId), true);
});

test('PolicyEngine - Refuses a replayed confirmation token the second time it is presented', () => {
  const engine = new PolicyEngine();
  const params = { command: 'git push origin main --force' };
  const report = BlastRadiusEngine.evaluate(params.command);
  const approval = TokenManager.generateToken(
    TOOL_NAME,
    'sha256:action-fingerprint',
    'supervisor@example.com',
    300
  );

  const firstUse = engine.evaluate(TOOL_NAME, params, report, approval.token);
  assert.strictEqual(firstUse.decision, PolicyDecision.ALLOW);

  const replay = engine.evaluate(TOOL_NAME, params, report, approval.token);

  assert.notStrictEqual(replay.decision, PolicyDecision.ALLOW);
  assert.strictEqual(replay.decision, PolicyDecision.REQUIRE_CONFIRMATION);
  assert.strictEqual(replay.tokenValid, false);
  assert.strictEqual(replay.requiresToken, true);
  assert.ok(replay.reasons.some((r) => r.includes('replay')));
});

test('PolicyEngine - Refuses an expired token and still demands confirmation', () => {
  const engine = new PolicyEngine();
  const params = { command: 'git push origin main --force' };
  const report = BlastRadiusEngine.evaluate(params.command);
  const expired = TokenManager.generateToken(
    TOOL_NAME,
    'sha256:action-fingerprint',
    'supervisor@example.com',
    -60
  );

  const result = engine.evaluate(TOOL_NAME, params, report, expired.token);

  assert.strictEqual(result.decision, PolicyDecision.REQUIRE_CONFIRMATION);
  assert.strictEqual(result.tokenValid, false);
  assert.ok(result.reasons.some((r) => r.includes('Token has expired')));
  assert.strictEqual(TokenManager.isConsumed(expired.payload.tokenId), false);
});

test('PolicyEngine - Applies a custom policy supplied to the constructor', () => {
  const customPolicy: SecurityPolicyConfig = {
    version: '9.9.9',
    name: 'Canary Deploy Guard',
    description: 'Blocks any request carrying an internal canary marker.',
    defaultDecision: PolicyDecision.ALLOW,
    rules: [
      {
        id: 'CT-001',
        name: 'Block Canary Deploy Marker',
        description: 'Blocks requests containing the org-specific canary marker.',
        enabled: true,
        action: PolicyDecision.BLOCK,
        forbiddenPatterns: ['canary-deploy-marker']
      }
    ]
  };
  const engine = new PolicyEngine(customPolicy);
  assert.strictEqual(engine.getPolicy().name, 'Canary Deploy Guard');

  const permitted = engine.evaluate(
    TOOL_NAME,
    { command: 'echo hello' },
    BlastRadiusEngine.evaluate('echo hello')
  );
  assert.strictEqual(permitted.decision, PolicyDecision.ALLOW);

  const blocked = engine.evaluate(
    TOOL_NAME,
    { command: 'deploy canary-deploy-marker' },
    BlastRadiusEngine.evaluate('deploy canary-deploy-marker')
  );
  assert.strictEqual(blocked.decision, PolicyDecision.BLOCK);
  assert.strictEqual(blocked.ruleMatched, 'CT-001');
  assert.ok(blocked.reasons.some((r) => r.includes('canary-deploy-marker')));
});

test('PolicyEngine - Falls back to a custom deny-by-default decision', () => {
  const denyAllPolicy: SecurityPolicyConfig = {
    version: '1.0.0',
    name: 'Deny All By Default',
    description: 'Blocks everything that no enabled rule explicitly permits.',
    defaultDecision: PolicyDecision.BLOCK,
    rules: []
  };
  const params = { command: 'cat README.md' };
  const report = BlastRadiusEngine.evaluate(params.command);

  const withShippedPolicy = new PolicyEngine().evaluate(TOOL_NAME, params, report);
  assert.strictEqual(withShippedPolicy.decision, PolicyDecision.ALLOW);

  const result = new PolicyEngine(denyAllPolicy).evaluate(TOOL_NAME, params, report);
  assert.strictEqual(result.decision, PolicyDecision.BLOCK);
  assert.strictEqual(result.ruleMatched, undefined);
  assert.strictEqual(result.requiresToken, false);
});

test('PolicyEngine - Honours a rule severityThreshold below the HIGH default', () => {
  const moderatePolicy: SecurityPolicyConfig = {
    version: '1.0.0',
    name: 'Moderate Risk Guard',
    description: 'Demands signed approval from MEDIUM severity upwards.',
    defaultDecision: PolicyDecision.ALLOW,
    rules: [
      {
        id: 'TH-001',
        name: 'Require Approval From Medium Up',
        description: 'Confirmation is required once MEDIUM severity is reached.',
        enabled: true,
        action: PolicyDecision.REQUIRE_CONFIRMATION,
        severityThreshold: SeverityLevel.MEDIUM
      }
    ]
  };
  const params = { command: 'npm version minor' };
  const moderateReport = reportAtSeverity(SeverityLevel.MEDIUM);

  const withShippedPolicy = new PolicyEngine().evaluate(TOOL_NAME, params, moderateReport);
  assert.strictEqual(withShippedPolicy.decision, PolicyDecision.ALLOW);

  const engine = new PolicyEngine(moderatePolicy);
  const result = engine.evaluate(TOOL_NAME, params, moderateReport);
  assert.strictEqual(result.decision, PolicyDecision.REQUIRE_CONFIRMATION);
  assert.strictEqual(result.ruleMatched, 'TH-001');
  assert.strictEqual(result.requiresToken, true);

  const lowResult = engine.evaluate(TOOL_NAME, params, reportAtSeverity(SeverityLevel.LOW));
  assert.strictEqual(lowResult.decision, PolicyDecision.ALLOW);
});

test('PolicyEngine - Ignores disabled rules when evaluating', () => {
  const disabledRulePolicy: SecurityPolicyConfig = {
    version: '1.0.0',
    name: 'Disabled Rule Policy',
    description: 'Carries the zero-trust block rule in a disabled state.',
    defaultDecision: PolicyDecision.ALLOW,
    rules: [
      {
        id: 'DS-001',
        name: 'Block Root Deletion (Disabled)',
        description: 'Present but switched off.',
        enabled: false,
        action: PolicyDecision.BLOCK,
        forbiddenPatterns: ['rm -rf /']
      }
    ]
  };
  const params = { command: 'rm -rf /' };

  const result = new PolicyEngine(disabledRulePolicy).evaluate(
    TOOL_NAME,
    params,
    BlastRadiusEngine.evaluate(params.command)
  );

  assert.notStrictEqual(result.decision, PolicyDecision.BLOCK);
  assert.strictEqual(result.decision, PolicyDecision.ALLOW);
  assert.strictEqual(result.ruleMatched, undefined);
});