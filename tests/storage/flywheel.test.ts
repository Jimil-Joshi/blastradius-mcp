import test from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DataFlywheel, dataFlywheel, RuleEnhancementRecord } from '../../src/storage/flywheel.js';
import { PostureCalculator, calculateSecurityPosture } from '../../src/security/postureCalculator.js';
import { SwarmSimulationRequest, SwarmSimulationResult } from '../../src/swarm/types.js';
import { PolicyEngine } from '../../src/policy/policyEngine.js';
import { BlastRadiusReport, SeverityLevel, ActionCategory, PolicyDecision } from '../../src/types.js';

test('DataFlywheel - initializes schema and tables in memory', () => {
  const flywheel = new DataFlywheel(':memory:');
  assert.ok(flywheel);

  const stats = flywheel.getStats();
  assert.strictEqual(stats.totalSimulations, 0);
  assert.strictEqual(stats.attackVectorsLearned, 0);
  assert.strictEqual(stats.enhancementsApplied, 0);
  assert.strictEqual(stats.pendingEnhancements, 0);
  assert.strictEqual(stats.averageRiskScore, 0);
  assert.deepStrictEqual(stats.topAttackVectors, []);

  flywheel.close();
});

test('DataFlywheel - records simulation result and attack vectors', () => {
  const flywheel = new DataFlywheel(':memory:');

  const request: SwarmSimulationRequest = {
    targetDiffOrCommand: 'SELECT * FROM users WHERE id = ${id}',
    contextDescription: 'User lookup endpoint refactor',
    agentCount: 25,
    intensity: 'FAST'
  };

  const result: SwarmSimulationResult = {
    simulationId: 'sim-test-001',
    prRiskScore: 85,
    verdict: 'BLOCK',
    personasSimulated: 25,
    divergenceFromStatic: 45,
    heatmapAscii: 'Heatmap',
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'SQL_INJECTION',
        severity: 'CRITICAL',
        description: 'Tainted user id in raw SQL query string',
        suggestedTest: 'test_sql_injection_rejection()',
        reproductionSteps: ["Send id=' OR 1=1--", "Verify all user records are returned"]
      },
      {
        personaType: 'CONFUSED_USER',
        attackVector: 'MALFORMED_INPUT',
        severity: 'LOW',
        description: 'Missing type coercion for id',
        suggestedTest: 'test_handles_empty_string()',
        reproductionSteps: ["Send id=''"]
      }
    ]
  };

  flywheel.recordSimulation(result, request);

  const stats = flywheel.getStats();
  assert.strictEqual(stats.totalSimulations, 1);
  assert.strictEqual(stats.attackVectorsLearned, 2);
  assert.strictEqual(stats.averageRiskScore, 85);
  assert.strictEqual(stats.topAttackVectors.length, 2);
  assert.strictEqual(stats.topAttackVectors[0].count, 1);

  flywheel.close();
});

test('DataFlywheel - generates rule enhancements for HIGH and CRITICAL findings and applies them', () => {
  const flywheel = new DataFlywheel(':memory:');

  const request: SwarmSimulationRequest = {
    targetDiffOrCommand: 'eval(req.body.code)',
    contextDescription: 'Dynamic code execution endpoint',
    agentCount: 10
  };

  const result: SwarmSimulationResult = {
    simulationId: 'sim-test-002',
    prRiskScore: 95,
    verdict: 'BLOCK',
    personasSimulated: 10,
    divergenceFromStatic: 60,
    heatmapAscii: '',
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'REMOTE_CODE_EXECUTION',
        severity: 'CRITICAL',
        description: 'Arbitrary code execution via eval()',
        suggestedTest: 'test_eval_blocked()'
      },
      {
        personaType: 'CONCURRENCY_RACER',
        attackVector: 'RACE_CONDITION_LOCK',
        severity: 'HIGH',
        description: 'Missing mutex around shared state',
        suggestedTest: 'test_concurrent_state_lock()'
      },
      {
        personaType: 'LEGACY_SYSTEM',
        attackVector: 'STALE_CACHE_HEADER',
        severity: 'MEDIUM',
        description: 'Cache header mismatch',
        suggestedTest: 'test_cache_headers()'
      }
    ]
  };

  flywheel.recordSimulation(result, request);

  // CRITICAL and HIGH findings should produce rule enhancements, but not MEDIUM
  const pending = flywheel.getPendingEnhancements();
  assert.strictEqual(pending.length, 2);
  assert.ok(pending.some((r: RuleEnhancementRecord) => r.name.includes('REMOTE_CODE_EXECUTION')));
  assert.ok(pending.some((r: RuleEnhancementRecord) => r.name.includes('RACE_CONDITION_LOCK')));
  assert.ok(!pending.some((r: RuleEnhancementRecord) => r.name.includes('STALE_CACHE_HEADER')));
  assert.strictEqual(pending.find((r: RuleEnhancementRecord) => r.name.includes('REMOTE_CODE_EXECUTION'))?.forbiddenPattern, 'remote_code_execution');
  assert.ok(!pending.some((r: RuleEnhancementRecord) => r.forbiddenPattern.includes('(?i)')));

  const statsBefore = flywheel.getStats();
  assert.strictEqual(statsBefore.pendingEnhancements, 2);
  assert.strictEqual(statsBefore.enhancementsApplied, 0);

  // Apply one enhancement
  const targetRule = pending[0];
  const applied = flywheel.applyEnhancement(targetRule.id);
  assert.strictEqual(applied, true);

  // Applying nonexistent id returns false
  assert.strictEqual(flywheel.applyEnhancement('non-existent-id'), false);

  const pendingAfter = flywheel.getPendingEnhancements();
  assert.strictEqual(pendingAfter.length, 1);

  const statsAfter = flywheel.getStats();
  assert.strictEqual(statsAfter.pendingEnhancements, 1);
  assert.strictEqual(statsAfter.enhancementsApplied, 1);

  flywheel.close();
});

test('DataFlywheel - calculates stats across multiple simulation runs', () => {
  const flywheel = new DataFlywheel(':memory:');

  const sim1: SwarmSimulationResult = {
    simulationId: 'sim-1',
    prRiskScore: 30,
    verdict: 'WARN',
    personasSimulated: 5,
    divergenceFromStatic: 10,
    heatmapAscii: '',
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'SQL_INJECTION',
        severity: 'HIGH',
        description: 'SQLi',
        suggestedTest: 'test()'
      }
    ]
  };

  const sim2: SwarmSimulationResult = {
    simulationId: 'sim-2',
    prRiskScore: 70,
    verdict: 'BLOCK',
    personasSimulated: 5,
    divergenceFromStatic: 20,
    heatmapAscii: '',
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'SQL_INJECTION',
        severity: 'CRITICAL',
        description: 'Second SQLi',
        suggestedTest: 'test()'
      },
      {
        personaType: 'HACKER',
        attackVector: 'AUTH_BYPASS',
        severity: 'CRITICAL',
        description: 'Auth bypass',
        suggestedTest: 'test()'
      }
    ]
  };

  flywheel.recordSimulation(sim1, { targetDiffOrCommand: 'diff1' });
  flywheel.recordSimulation(sim2, { targetDiffOrCommand: 'diff2' });

  const stats = flywheel.getStats();
  assert.strictEqual(stats.totalSimulations, 2);
  assert.strictEqual(stats.attackVectorsLearned, 3);
  assert.strictEqual(stats.averageRiskScore, 50); // (30 + 70) / 2
  assert.strictEqual(stats.topAttackVectors[0].vector, 'SQL_INJECTION');
  assert.strictEqual(stats.topAttackVectors[0].count, 2);
  assert.strictEqual(stats.topAttackVectors[1].vector, 'AUTH_BYPASS');
  assert.strictEqual(stats.topAttackVectors[1].count, 1);

  flywheel.close();
});

test('DataFlywheel - records audit events', () => {
  const flywheel = new DataFlywheel(':memory:');

  flywheel.recordAuditEvent({
    toolName: 'route_tool',
    callerId: 'agent-123',
    decision: 'ALLOW',
    riskScore: 12,
    hash: 'abcdef1234567890'
  });

  // Verify close cleans up without error
  flywheel.close();
});

test('PostureCalculator - computes real-time security posture and flywheel telemetry', () => {
  const flywheel = new DataFlywheel(':memory:');

  flywheel.recordSimulation(
    {
      simulationId: 'sim-posture-1',
      prRiskScore: 40,
      verdict: 'WARN',
      personasSimulated: 10,
      divergenceFromStatic: 15,
      heatmapAscii: '',
      criticalFindings: [
        {
          personaType: 'HACKER',
          attackVector: 'CROSS_SITE_SCRIPTING',
          severity: 'HIGH',
          description: 'Reflected XSS in query param',
          suggestedTest: 'test_xss()'
        }
      ]
    },
    { targetDiffOrCommand: 'const html = req.query.msg' }
  );

  const posture = PostureCalculator.calculate({
    auditChainIntact: true,
    activePolicy: 'Strict-Zero-Trust',
    totalInvocations: 100,
    blockedCount: 2,
    dlpRedactionsCount: 1,
    flywheel
  });

  assert.strictEqual(posture.edition, 'open-source');
  assert.strictEqual(posture.activePolicy, 'Strict-Zero-Trust');
  assert.strictEqual(posture.auditChain.intact, true);
  assert.strictEqual(posture.auditChain.tampered, false);
  assert.strictEqual(posture.metrics.totalInvocations, 100);
  assert.strictEqual(posture.metrics.blockedCount, 2);
  assert.strictEqual(posture.metrics.dlpRedactionsCount, 1);
  assert.strictEqual(posture.flywheel.totalSimulations, 1);
  assert.strictEqual(posture.flywheel.attackVectorsLearned, 1);
  assert.strictEqual(posture.flywheel.pendingEnhancements, 1);
  assert.ok(posture.overallScore >= 0 && posture.overallScore <= 100);
  assert.strictEqual(posture.status, 'WARNING'); // blockedCount > 0 or pending enhancements triggers WARNING

  flywheel.close();
});

test('PostureCalculator - flags tampered audit chains with ALERT and lower score', () => {
  const posture = calculateSecurityPosture({
    auditChainIntact: false,
    activePolicy: 'Default',
    totalInvocations: 10,
    blockedCount: 0,
    dlpRedactionsCount: 0
  });

  assert.strictEqual(posture.auditChain.intact, false);
  assert.strictEqual(posture.auditChain.tampered, true);
  assert.strictEqual(posture.status, 'ALERT');
  assert.ok(posture.overallScore <= 50);
});

test('DataFlywheel - singleton instance is exported and responsive', () => {
  assert.ok(dataFlywheel);
  const stats = dataFlywheel.getStats();
  assert.strictEqual(typeof stats.totalSimulations, 'number');
});

test('DataFlywheel - persists data across instances using real file path with WAL mode', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-flywheel-'));
  const dbFile = path.join(tmpDir, 'test-flywheel.db');

  try {
    const fw1 = new DataFlywheel(dbFile);
    fw1.recordAuditEvent({
      toolName: 'test_tool',
      callerId: 'agent-1',
      decision: 'ALLOW',
      riskScore: 10,
      hash: 'hash-1'
    });
    fw1.recordSimulation(
      {
        simulationId: 'sim-persist-1',
        prRiskScore: 90,
        verdict: 'BLOCK',
        personasSimulated: 5,
        divergenceFromStatic: 20,
        heatmapAscii: '',
        criticalFindings: [
          {
            personaType: 'HACKER',
            attackVector: 'SQL_INJECTION',
            severity: 'CRITICAL',
            description: 'SQLi detected',
            suggestedTest: 'test_sqli()'
          }
        ]
      },
      { targetDiffOrCommand: 'DROP TABLE users;' }
    );
    const stats1 = fw1.getStats();
    assert.strictEqual(stats1.totalSimulations, 1);
    assert.strictEqual(stats1.pendingEnhancements, 1);
    fw1.close();

    // Verify file exists on disk
    assert.ok(fs.existsSync(dbFile));

    // Reopen in a second DataFlywheel instance and verify persistence
    const fw2 = new DataFlywheel(dbFile);
    const stats2 = fw2.getStats();
    assert.strictEqual(stats2.totalSimulations, 1);
    assert.strictEqual(stats2.pendingEnhancements, 1);
    assert.strictEqual(stats2.attackVectorsLearned, 1);

    // Verify rule enhancement pattern is normalized and compatible with PolicyEngine
    const pending = fw2.getPendingEnhancements();
    assert.strictEqual(pending.length, 1);
    assert.strictEqual(pending[0].forbiddenPattern, 'sql_injection');
    assert.ok(!pending[0].forbiddenPattern.includes('(?i)'));

    fw2.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('DataFlywheel - gracefully falls back to :memory: if directory cannot be created', () => {
  const invalidPath = 'Z:\\non_existent_impossible_directory_9999\\flywheel.db';
  const fw = new DataFlywheel(invalidPath);
  assert.ok(fw);
  const stats = fw.getStats();
  assert.strictEqual(stats.totalSimulations, 0);
  fw.close();
});

test('DataFlywheel - wraps writes in atomic transaction and rolls back on failure', () => {
  const fw = new DataFlywheel(':memory:');
  const validRequest = { targetDiffOrCommand: 'ls' };
  const validResult: SwarmSimulationResult = {
    simulationId: 'sim-valid',
    prRiskScore: 10,
    verdict: 'SAFE',
    personasSimulated: 5,
    divergenceFromStatic: 0,
    heatmapAscii: '',
    criticalFindings: []
  };

  fw.recordSimulation(validResult, validRequest);
  assert.strictEqual(fw.getStats().totalSimulations, 1);

  // Attempt to record duplicate simulationId which will violate PRIMARY KEY constraint
  const badResult: SwarmSimulationResult = {
    ...validResult,
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'TEST_ROLLBACK_VECTOR',
        severity: 'CRITICAL',
        description: 'Should not be inserted',
        suggestedTest: 'test()'
      }
    ]
  };

  assert.throws(() => {
    fw.recordSimulation(badResult, validRequest);
  });

  // Verify atomic rollback: attack vectors and rule enhancements were not inserted
  const stats = fw.getStats();
  assert.strictEqual(stats.totalSimulations, 1);
  assert.strictEqual(stats.attackVectorsLearned, 0);
  assert.strictEqual(stats.pendingEnhancements, 0);

  fw.close();
});

test('DataFlywheel - generated rule enhancements are compatible with PolicyEngine', () => {
  const fw = new DataFlywheel(':memory:');
  fw.recordSimulation(
    {
      simulationId: 'sim-policy-check',
      prRiskScore: 95,
      verdict: 'BLOCK',
      personasSimulated: 5,
      divergenceFromStatic: 30,
      heatmapAscii: '',
      criticalFindings: [
        {
          personaType: 'HACKER',
          attackVector: 'SQL_INJECTION',
          severity: 'CRITICAL',
          description: 'SQL injection detected',
          suggestedTest: 'test()'
        }
      ]
    },
    { targetDiffOrCommand: 'SELECT * FROM users' }
  );

  const pending = fw.getPendingEnhancements();
  assert.strictEqual(pending.length, 1);
  const ruleRecord = pending[0];

  // Configure PolicyEngine with a policy rule utilizing the generated forbiddenPattern
  const engine = new PolicyEngine({
    version: '1.0.0',
    name: 'Dynamic Learned Policy',
    description: 'Policy generated from flywheel',
    defaultDecision: PolicyDecision.ALLOW,
    rules: [
      {
        id: ruleRecord.generatedRuleId,
        name: ruleRecord.name,
        description: 'Auto mitigation rule',
        action: PolicyDecision.BLOCK,
        enabled: true,
        forbiddenPatterns: [ruleRecord.forbiddenPattern]
      }
    ]
  });

  const dummyReport: BlastRadiusReport = {
    dangerScore: 10,
    severity: SeverityLevel.LOW,
    category: ActionCategory.SHELL,
    reasons: [],
    affectedEntities: [],
    destructive: false,
    irreversible: false,
    rollbackFeasible: true,
    recommendedMitigations: []
  };

  // Evaluate matching payload
  const result = engine.evaluate('test_tool', { query: 'exploit_sql_injection_payload' }, dummyReport);
  assert.strictEqual(result.decision, PolicyDecision.BLOCK);
  assert.strictEqual(result.ruleMatched, ruleRecord.generatedRuleId);

  fw.close();
});

