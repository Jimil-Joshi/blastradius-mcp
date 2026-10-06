import test from 'node:test';
import assert from 'node:assert';
import { BlastRadiusEngine } from '../src/analyzer/blastRadiusEngine.js';
import { ActionCategory, SeverityLevel } from '../src/types.js';

test('BlastRadiusEngine - Evaluates rm -rf / as CRITICAL and destructive', () => {
  const report = BlastRadiusEngine.evaluate('rm -rf /');

  assert.strictEqual(report.dangerScore, 100);
  assert.strictEqual(report.severity, SeverityLevel.CRITICAL);
  assert.strictEqual(report.destructive, true);
  assert.strictEqual(report.irreversible, true);
  assert.strictEqual(report.rollbackFeasible, false);
  assert.ok(report.reasons.some((r) => r.includes('root, home, or wildcard')));
});

test('BlastRadiusEngine - Evaluates DROP DATABASE as CRITICAL and SQL category', () => {
  const report = BlastRadiusEngine.evaluate('DROP DATABASE analytics_warehouse;');

  assert.strictEqual(report.category, ActionCategory.SQL);
  assert.strictEqual(report.dangerScore, 100);
  assert.strictEqual(report.severity, SeverityLevel.CRITICAL);
  assert.strictEqual(report.destructive, true);
  assert.ok(report.affectedEntities.some((e) => e.includes('analytics_warehouse')));
});

test('BlastRadiusEngine - Evaluates AWS terminate-instances as CRITICAL', () => {
  const report = BlastRadiusEngine.evaluate(
    'aws ec2 terminate-instances --instance-ids i-0123456789abcdef0'
  );

  assert.strictEqual(report.category, ActionCategory.CLOUD);
  assert.strictEqual(report.severity, SeverityLevel.CRITICAL);
  assert.strictEqual(report.destructive, true);
  assert.ok(report.affectedEntities.some((e) => e.includes('i-0123456789abcdef0')));
});

test('BlastRadiusEngine - Evaluates git push --force as HIGH danger', () => {
  const report = BlastRadiusEngine.evaluate('git push origin main --force');

  assert.strictEqual(report.severity, SeverityLevel.HIGH);
  assert.strictEqual(report.destructive, true);
  assert.ok(report.reasons.some((r) => r.includes('Destructive git command')));
});

test('BlastRadiusEngine - Read operation produces SAFE severity', () => {
  const report = BlastRadiusEngine.evaluate('SELECT id, name FROM users WHERE id = 42;');

  assert.strictEqual(report.category, ActionCategory.SQL);
  assert.strictEqual(report.severity, SeverityLevel.SAFE);
  assert.strictEqual(report.destructive, false);
  assert.strictEqual(report.rollbackFeasible, true);
});

/**
 * The real input shape. `server.ts` and `mcpProxy.ts` both reach the engine as
 * `JSON.stringify(params)`, so a tool call carrying an argv-shaped object is
 * what every MCP request actually looks like — and it is the case the old
 * single-string path silently scored 5.
 */
test('BlastRadiusEngine - Scores an argv-shaped MCP parameter object as destructive', () => {
  const params = { command: 'rm', args: ['-rf', '/'] };
  const report = BlastRadiusEngine.evaluate(JSON.stringify(params));

  assert.ok(
    report.dangerScore >= 70,
    `structured params scored ${report.dangerScore}; a root delete must not read as routine`
  );
  assert.strictEqual(report.destructive, true);
  assert.ok(
    report.reasons.some((r) => r.includes('structured tool parameters')),
    `expected the structured-parameter reason, got: ${report.reasons.join(' | ')}`
  );
});

test('BlastRadiusEngine - Takes the worst field rather than the first', () => {
  // An innocuous field must not displace a destructive one sitting beside it.
  const report = BlastRadiusEngine.evaluate(
    JSON.stringify({ tool: 'bash', command: 'terraform', args: ['destroy', '-auto-approve'] })
  );
  assert.ok(report.dangerScore >= 70, `expected the destructive field to win, got ${report.dangerScore}`);
});

test('BlastRadiusEngine - Does not read prose as an invocation', () => {
  // `echo ready` is reassembled from the argv fields and legitimately carries the
  // structured-parameter note. What must not happen is the description text
  // raising the score: those words are documentation, not an invocation.
  const report = BlastRadiusEngine.evaluate(
    JSON.stringify({
      command: 'echo',
      args: ['ready'],
      description: 'Refuses rm -rf / and drop table. Do not shred files.'
    })
  );
  assert.ok(
    report.dangerScore < 70,
    `prose in a description field scored ${report.dangerScore}: ${report.reasons.join(' | ')}`
  );
  assert.strictEqual(report.destructive, false);
});

test('BlastRadiusEngine - Production context escalates danger score', () => {
  const stagingReport = BlastRadiusEngine.evaluate('DROP TABLE temp_logs;', ActionCategory.SQL, {
    environment: 'staging'
  });
  const prodReport = BlastRadiusEngine.evaluate('DROP TABLE temp_logs;', ActionCategory.SQL, {
    environment: 'production'
  });

  assert.ok(prodReport.dangerScore >= stagingReport.dangerScore);
  assert.ok(prodReport.reasons.some((r) => r.includes('PRODUCTION')));
});
