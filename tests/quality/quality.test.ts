import test from 'node:test';
import assert from 'node:assert';
import * as path from 'node:path';
import * as fs from 'node:fs';
import {
  TddStateMachine,
  TddPhase,
  generateSocraticSpec,
  WorktreeManager,
  critiqueCode,
  tddStateMachine,
  worktreeManager
} from '../../src/quality/index.js';

test('TddStateMachine - initial state and phase management', () => {
  const machine = new TddStateMachine();
  const feature = 'auth-token-refresh';

  const initial = machine.getState(feature);
  assert.strictEqual(initial.activeFeature, feature);
  assert.strictEqual(initial.phase, TddPhase.IDLE);
  assert.deepStrictEqual(initial.allowedWritePaths, []);

  // Production code edits blocked in IDLE
  const prodCheck = machine.canModifyProductionCode(feature, 'src/auth/tokenService.ts');
  assert.strictEqual(prodCheck.allowed, false);
  assert.match(prodCheck.reason || '', /Agent cannot modify production code until a failing test is written/);

  // Test code edits allowed even in IDLE
  const testCheck = machine.canModifyProductionCode(feature, 'tests/auth/tokenService.test.ts');
  assert.strictEqual(testCheck.allowed, true);
  assert.strictEqual(testCheck.reason, undefined);

  // Alternative test path patterns (specs, __tests__)
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/__tests__/auth.spec.ts').allowed, true);
  assert.strictEqual(machine.canModifyProductionCode(feature, 'test/helpers.ts').allowed, true);
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/auth_test.ts').allowed, true);
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/auth-spec.ts').allowed, true);

  // Strict boundary check: words containing 'test' or 'spec' as substrings are production files and MUST be blocked
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/game/contestant.ts').allowed, false);
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/view/spectator.ts').allowed, false);
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/render/perspective.ts').allowed, false);
});

test('TddStateMachine - Red phase workflow and test failure verification', () => {
  const machine = new TddStateMachine();
  const feature = 'dlp-masking';

  // Register failing test
  const registered = machine.registerFailingTest(
    feature,
    'tests/dlp/masking.test.ts',
    'should mask credit card numbers with asterisks'
  );
  assert.strictEqual(registered.phase, TddPhase.RED_PENDING);
  assert.strictEqual(registered.failingTestPath, 'tests/dlp/masking.test.ts');
  assert.strictEqual(registered.failingTestAssertion, 'should mask credit card numbers with asterisks');
  assert.ok(registered.allowedWritePaths.includes('tests/dlp/masking.test.ts'));

  // In RED_PENDING: production edits still blocked
  const prodCheck = machine.canModifyProductionCode(feature, 'src/dlp/masking.ts');
  assert.strictEqual(prodCheck.allowed, false);
  assert.match(prodCheck.reason || '', /RED phase/);

  // In RED_PENDING: test edits allowed
  const testCheck = machine.canModifyProductionCode(feature, 'tests/dlp/masking.test.ts');
  assert.strictEqual(testCheck.allowed, true);

  // Verifying with passing output should NOT advance to RED_CONFIRMED
  const falsePass = machine.verifyTestFailure(feature, '✔ all 4 tests passed, 0 failed');
  assert.strictEqual(falsePass.verified, false);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.RED_PENDING);

  // Verifying with legitimate test failure output transitions to RED_CONFIRMED
  const failureOutput = `
    ✖ should mask credit card numbers with asterisks
      AssertionError: expected '4111-2222-3333-4444' to equal '****-****-****-4444'
          at Context.<anonymous> (tests/dlp/masking.test.ts:15:7)
      failed 1 test
  `;
  const failureResult = machine.verifyTestFailure(feature, failureOutput);
  assert.strictEqual(failureResult.verified, true);
  assert.strictEqual(failureResult.state.phase, TddPhase.RED_CONFIRMED);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.RED_CONFIRMED);
});

test('TddStateMachine - Green phase verification and transition to REFACTOR', () => {
  const machine = new TddStateMachine();
  const feature = 'rate-limiter';

  // Advance to RED_CONFIRMED
  machine.registerFailingTest(feature, 'tests/rateLimiter.test.ts', 'should return 429 on limit');
  machine.verifyTestFailure(feature, 'AssertionError: expected 200 to equal 429');
  assert.strictEqual(machine.getState(feature).phase, TddPhase.RED_CONFIRMED);

  // Now production code edit IS allowed and advances state to GREEN_PENDING
  const prodCheck = machine.canModifyProductionCode(feature, 'src/rateLimiter.ts');
  assert.strictEqual(prodCheck.allowed, true);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.GREEN_PENDING);

  // Explicit startGreenPhase also works idempotently
  machine.startGreenPhase(feature);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.GREEN_PENDING);

  // Attempting verifyTestPass while tests still fail should fail
  const stillFailing = machine.verifyTestPass(feature, 'AssertionError: expected 200 to equal 429\nfailed 1 test');
  assert.strictEqual(stillFailing.verified, false);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.GREEN_PENDING);

  // Verifying clean passing output transitions to REFACTOR
  const passOutput = `
    ✔ should allow requests under limit
    ✔ should return 429 on limit
    ℹ tests 2
    ℹ pass 2
    ℹ fail 0
    ok
  `;
  const passResult = machine.verifyTestPass(feature, passOutput);
  assert.strictEqual(passResult.verified, true);
  assert.strictEqual(passResult.state.phase, TddPhase.REFACTOR);
  assert.ok(passResult.state.greenVerificationTimestamp);

  // In REFACTOR, production edits remain allowed
  assert.strictEqual(machine.canModifyProductionCode(feature, 'src/rateLimiter.ts').allowed, true);

  // Reset feature state
  machine.reset(feature);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.IDLE);
});

test('TddStateMachine - verifyTestPass handles test titles with Error: and logs cleanly', () => {
  const machine = new TddStateMachine();
  const feature = 'error-handling';

  machine.registerFailingTest(feature, 'tests/error.test.ts', 'should catch error');
  machine.verifyTestFailure(feature, 'AssertionError: expected error to be caught');
  machine.startGreenPhase(feature);

  // Test suite output where passed test description contains "Error:"
  const passOutputWithErrorTitle = `
    ✔ validates Error: bad input was caught successfully
    ✔ handles AssertionError message formatting without crashing
    ℹ tests 2
    ℹ pass 2
    ℹ fail 0
    ok
  `;
  const result = machine.verifyTestPass(feature, passOutputWithErrorTitle);
  assert.strictEqual(result.verified, true);
  assert.strictEqual(result.state.phase, TddPhase.REFACTOR);
});

test('TddStateMachine - cannot verify test pass without confirmed RED phase', () => {
  const machine = new TddStateMachine();
  const feature = 'untested-feature';

  const result = machine.verifyTestPass(feature, 'all 5 tests passed');
  assert.strictEqual(result.verified, false);
  assert.match(result.message, /RED phase must be confirmed/);
  assert.strictEqual(machine.getState(feature).phase, TddPhase.IDLE);
});

test('SocraticSpec - generates rigorous specification with edge cases and test plan', () => {
  const spec = generateSocraticSpec(
    'Implement Redis-backed sliding window rate limiter for MCP tool calls',
    ['gateway', 'redis', 'security'],
    'DETAILED'
  );

  assert.ok(spec.featureName);
  assert.ok(spec.summary.length > 20);
  assert.ok(spec.invariants.length >= 3);
  assert.ok(spec.preconditions.length >= 2);
  assert.ok(spec.postconditions.length >= 2);

  // Edge cases must include all required categories
  const edgeScenarios = spec.edgeCases.map(e => e.scenario.toLowerCase()).join(' ');
  assert.ok(edgeScenarios.includes('empty') || edgeScenarios.includes('null'));
  assert.ok(edgeScenarios.includes('concurrency') || edgeScenarios.includes('race'));
  assert.ok(edgeScenarios.includes('boundar') || edgeScenarios.includes('numeric'));
  assert.ok(edgeScenarios.includes('unicode') || edgeScenarios.includes('special'));
  assert.ok(edgeScenarios.includes('timeout') || edgeScenarios.includes('network') || edgeScenarios.includes('outage'));

  // Security & DLP requirements
  assert.ok(spec.securityRequirements.length >= 3);
  const secJoined = spec.securityRequirements.join(' ').toLowerCase();
  assert.ok(secJoined.includes('auth') || secJoined.includes('sanitiz') || secJoined.includes('credential'));

  // Test plan with RED tests
  assert.ok(spec.testPlan.length >= 3);
  for (const item of spec.testPlan) {
    assert.ok(item.testName);
    assert.ok(item.description);
    assert.ok(item.assertionHint);
  }

  // Markdown output
  assert.ok(spec.markdownSpec.includes('# Socratic Specification'));
  assert.ok(spec.markdownSpec.includes('## User Intent & Core Invariants'));
  assert.ok(spec.markdownSpec.includes('## Edge Cases'));
  assert.ok(spec.markdownSpec.includes('## Concrete Test Verification Plan'));
});

test('SocraticSpec - handles HIGH_LEVEL and EXHAUSTIVE depths', () => {
  const highLevel = generateSocraticSpec('Add audit logging', undefined, 'HIGH_LEVEL');
  assert.ok(highLevel.edgeCases.length >= 3);
  assert.ok(highLevel.testPlan.length >= 2);

  const exhaustive = generateSocraticSpec('Distributed lock manager', ['redis', 'cluster'], 'EXHAUSTIVE');
  assert.ok(exhaustive.edgeCases.length >= 6);
  assert.ok(exhaustive.testPlan.length >= 4);
  assert.ok(exhaustive.invariants.length >= 4);
});

test('WorktreeManager - isolated worktree lifecycle operations', async () => {
  const manager = new WorktreeManager();
  const testAgentId = 'agent-quality-test-' + Date.now();
  const branchName = 'feat/test-worktree-' + Date.now();

  const spawnResult = await manager.spawnWorktree(testAgentId, branchName);
  assert.strictEqual(spawnResult.agentId, testAgentId);
  assert.strictEqual(spawnResult.branchName, branchName);
  assert.ok(spawnResult.worktreePath);
  assert.ok(['CREATED', 'ACTIVE'].includes(spawnResult.status));

  // Should show up in listWorktrees
  const list = await manager.listWorktrees();
  assert.ok(list.some(w => w.agentId === testAgentId));

  // Cleanup worktree
  const cleanup = await manager.cleanupWorktree(testAgentId);
  assert.strictEqual(cleanup.success, true);

  // Non-existent cleanup handles gracefully
  const secondCleanup = await manager.cleanupWorktree('non-existent-agent-xyz');
  assert.strictEqual(secondCleanup.success, true);
});

test('WorktreeManager - rejects branchName or baseBranch with git option injection', async () => {
  const manager = new WorktreeManager();
  await assert.rejects(
    () => manager.spawnWorktree('agent-opt-1', '--upload-pack=evil'),
    /git option injection/i
  );
  await assert.rejects(
    () => manager.spawnWorktree('agent-opt-2', '-b'),
    /git option injection/i
  );
  await assert.rejects(
    () => manager.spawnWorktree('agent-opt-3', 'valid_branch', '--output=/tmp/pwn'),
    /git option injection/i
  );
  await assert.rejects(
    () => manager.spawnWorktree('agent-opt-4', 'invalid;branch'),
    /git option injection/i
  );
});

test('AutomatedCodeCritique - flags empty catch blocks and swallowed errors', () => {
  const codeWithEmptyCatch = `
    try {
      dangerousAction();
    } catch (e) {
    }
  `;
  const result = critiqueCode(codeWithEmptyCatch, 'src/service.ts');
  const finding = result.findings.find(f => f.ruleId === 'NO_EMPTY_CATCH');
  assert.ok(finding, 'Should flag empty catch block');
  assert.strictEqual(finding?.severity, 'HIGH');
  assert.strictEqual(finding?.category, 'ERROR_HANDLING');
  assert.ok(result.score < 100);
});

test('AutomatedCodeCritique - flags dangerous shell sinks', () => {
  const codeWithShellSink = `
    const { exec } = require('child_process');
    function runUserCommand(input) {
      eval(input);
      return exec(input);
    }
  `;
  const result = critiqueCode(codeWithShellSink, 'src/executor.ts');
  const sinks = result.findings.filter(f => f.ruleId === 'DANGEROUS_SHELL_SINK');
  assert.ok(sinks.length >= 2, 'Should flag eval and exec sinks');
  assert.ok(sinks.some(s => s.severity === 'CRITICAL'));
  assert.strictEqual(result.passed, false);
});

test('AutomatedCodeCritique - flags missing assertions in test files', () => {
  const testWithoutAssert = `
    test('renders widget correctly', () => {
      const widget = renderWidget();
      widget.click();
    });
  `;
  const result = critiqueCode(testWithoutAssert, 'tests/widget.test.ts');
  const finding = result.findings.find(f => f.ruleId === 'MISSING_TEST_ASSERTION');
  assert.ok(finding, 'Should flag test without assertions');
  assert.strictEqual(finding?.category, 'QUALITY');

  // Test with proper assert should not flag
  const testWithAssert = `
    test('renders widget correctly', () => {
      const widget = renderWidget();
      assert.strictEqual(widget.isVisible(), true);
    });
  `;
  const cleanResult = critiqueCode(testWithAssert, 'tests/widget.test.ts');
  assert.strictEqual(cleanResult.findings.some(f => f.ruleId === 'MISSING_TEST_ASSERTION'), false);
});

test('AutomatedCodeCritique - flags unchecked external input and unbounded queries', () => {
  const badCode = `
    app.post('/profile', (req, res) => {
      const bio = req.body.bio;
      const sql = 'SELECT * FROM users WHERE active = true';
      db.query(sql);
    });
  `;
  const result = critiqueCode(badCode, 'src/controllers/user.ts');
  const unchecked = result.findings.find(f => f.ruleId === 'UNCHECKED_INPUT');
  assert.ok(unchecked, 'Should flag direct unchecked req.body access');

  const unbounded = result.findings.find(f => f.ruleId === 'UNBOUNDED_DB_QUERY');
  assert.ok(unbounded, 'Should flag SELECT without LIMIT');
  assert.strictEqual(unbounded?.category, 'PERFORMANCE');
});

test('AutomatedCodeCritique - scores clean code with 100 and passes strict security', () => {
  const cleanCode = `
    import { z } from 'zod';

    const RequestSchema = z.object({ name: z.string().min(1) });

    export function handleRequest(raw: unknown) {
      try {
        const validated = RequestSchema.parse(raw);
        const query = 'SELECT id, name FROM users WHERE id = ? LIMIT 10';
        return { success: true, data: validated, query };
      } catch (err) {
        console.error('Request validation failed:', err);
        throw err;
      }
    }
  `;
  const result = critiqueCode(cleanCode, 'src/handler.ts', true);
  assert.strictEqual(result.score, 100);
  assert.strictEqual(result.passed, true);
  assert.strictEqual(result.findingsCount, 0);
  assert.strictEqual(result.findings.length, 0);
});

test('AutomatedCodeCritique - does not flag RegExp.exec() as a shell sink', () => {
  const codeWithRegexExec = `
    const pattern = /hello/g;
    const match = pattern.exec('hello world');
  `;
  const result = critiqueCode(codeWithRegexExec, 'src/parser.ts');
  const sinks = result.findings.filter(f => f.ruleId === 'DANGEROUS_SHELL_SINK');
  assert.strictEqual(sinks.length, 0);
});

test('AutomatedCodeCritique - flags multi-line unbounded SQL queries in template strings', () => {
  const codeWithMultilineSql = `
    const query = \`
      SELECT id, name, email
      FROM users
      WHERE active = true
    \`;
  `;
  const result = critiqueCode(codeWithMultilineSql, 'src/repo.ts');
  const unbounded = result.findings.find(f => f.ruleId === 'UNBOUNDED_DB_QUERY');
  assert.ok(unbounded, 'Should flag multi-line SELECT without LIMIT');
  assert.strictEqual(unbounded?.category, 'PERFORMANCE');
});

test('Quality Module - singleton instances exported and synchronized with class getInstance', () => {
  assert.ok(tddStateMachine instanceof TddStateMachine);
  assert.ok(worktreeManager instanceof WorktreeManager);
  assert.strictEqual(tddStateMachine, TddStateMachine.getInstance());
  assert.strictEqual(worktreeManager, WorktreeManager.getInstance());
});
