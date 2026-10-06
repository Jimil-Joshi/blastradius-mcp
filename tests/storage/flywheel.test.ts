import test from 'node:test';
import assert from 'node:assert';
import { DataFlywheel, dataFlywheel, RuleEnhancementRecord } from '../../src/storage/flywheel.js';
import { PostureCalculator, calculateSecurityPosture } from '../../src/security/postureCalculator.js';
import { SwarmSimulationRequest, SwarmSimulationResult } from '../../src/swarm/types.js';

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
