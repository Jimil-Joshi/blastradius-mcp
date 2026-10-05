import test from 'node:test';
import assert from 'node:assert';
import { DLPScanner } from '../src/analyzer/dlpScanner.js';
import { SeverityLevel } from '../src/types.js';

test('DLPScanner - Detects AWS Access Keys', () => {
  const text = 'Configured AWS with AKIAIOSFODNN7EXAMPLE for deployment';
  const result = DLPScanner.scan(text, true);

  assert.strictEqual(result.hasFindings, true);
  assert.strictEqual(result.findings[0].type, 'AWS_ACCESS_KEY');
  assert.strictEqual(result.findings[0].severity, SeverityLevel.CRITICAL);
  assert.ok(result.sanitizedContent.includes('[REDACTED_AWS_KEY:'));
  assert.ok(!result.sanitizedContent.includes('AKIAIOSFODNN7EXAMPLE'));
});

test('DLPScanner - Detects GitHub PAT Tokens', () => {
  const text = 'export GITHUB_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwx"';
  const result = DLPScanner.scan(text, true);

  assert.strictEqual(result.hasFindings, true);
  assert.strictEqual(result.findings[0].type, 'GITHUB_PAT');
  assert.ok(result.sanitizedContent.includes('[REDACTED_GITHUB_TOKEN:'));
});

test('DLPScanner - Detects Database Connection URI Passwords', () => {
  const text = 'Database URL: postgres://admin:superSecretPass123@db.example.com:5432/mydb';
  const result = DLPScanner.scan(text, true);

  assert.strictEqual(result.hasFindings, true);
  assert.ok(result.sanitizedContent.includes('postgres://admin:[REDACTED_PASSWORD]@db.example.com'));
  assert.ok(!result.sanitizedContent.includes('superSecretPass123'));
});

test('DLPScanner - Detects Credit Cards and SSNs', () => {
  const text = 'Customer payment: CC: 4532015698741236, SSN: 000-12-3456';
  const result = DLPScanner.scan(text, true);

  assert.strictEqual(result.hasFindings, true);
  assert.strictEqual(result.findingsCount, 2);
  assert.ok(result.sanitizedContent.includes('[REDACTED_CREDIT_CARD:'));
  assert.ok(result.sanitizedContent.includes('[REDACTED_US_SSN:'));
  assert.ok(!result.sanitizedContent.includes('4532015698741236'));
  assert.ok(!result.sanitizedContent.includes('000-12-3456'));
});

test('DLPScanner - Clean payload returns zero findings', () => {
  const text = 'Standard log entry: application server initialized successfully on port 8080';
  const result = DLPScanner.scan(text, true);

  assert.strictEqual(result.hasFindings, false);
  assert.strictEqual(result.findingsCount, 0);
  assert.strictEqual(result.sanitizedContent, text);
});
