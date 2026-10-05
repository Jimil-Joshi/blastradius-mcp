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
