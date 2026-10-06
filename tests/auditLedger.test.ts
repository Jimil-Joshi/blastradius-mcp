import test, { after, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AuditLedger } from '../src/security/auditLedger.js';
import { ActionCategory, AuditEntry, PolicyDecision, SeverityLevel } from '../src/types.js';

const GENESIS_HASH = '0'.repeat(64);

// The ledger writes to process.cwd() by default, so every test in this file is
// pointed at a throwaway directory instead of the repository.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-ledger-'));
const ledgerFile = path.join(tmpDir, 'blastradius-audit.jsonl');

function recordSample(
  dangerScore: number,
  severity: SeverityLevel,
  rawPayload: Record<string, unknown>
): AuditEntry {
  return AuditLedger.record({
    toolName: 'enforce_policy',
    callerId: 'agent-client',
    category: ActionCategory.SHELL,
    decision: PolicyDecision.REQUIRE_CONFIRMATION,
    dangerScore,
    severity,
    reasons: ['Elevated risk. Cryptographic confirmation token required to proceed.'],
    dlpFindingsCount: 0,
    rawPayload
  });
}

function readOnDisk(): AuditEntry[] {
  return fs
    .readFileSync(ledgerFile, 'utf-8')
    .trim()
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as AuditEntry);
}

function writeOnDisk(entries: AuditEntry[]): void {
  const body = entries.map((entry) => JSON.stringify(entry)).join('\n');
  fs.writeFileSync(ledgerFile, body + '\n', 'utf-8');
}

beforeEach(() => {
  fs.rmSync(ledgerFile, { force: true });
  AuditLedger.initialize(ledgerFile);
});

after(() => {
  AuditLedger.reset();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('AuditLedger - Chains entries from a genesis hash and verifies them as intact', () => {
  const first = recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  const second = recordSample(85, SeverityLevel.HIGH, { command: 'git push origin main --force' });
  const third = recordSample(5, SeverityLevel.SAFE, { command: 'ls' });

  assert.strictEqual(first.index, 0);
  assert.strictEqual(first.prevHash, GENESIS_HASH);
  assert.strictEqual(second.prevHash, first.currentHash);
  assert.strictEqual(third.prevHash, second.currentHash);
  assert.ok(first.currentHash.match(/^[0-9a-f]{64}$/));
  assert.ok(first.signature.match(/^[0-9a-f]{64}$/));

  const verification = AuditLedger.verifyIntegrity();
  assert.strictEqual(verification.intact, true);
  assert.strictEqual(verification.totalEntries, 3);
  assert.strictEqual(verification.verifiedCount, 3);
  assert.strictEqual(verification.tamperedIndex, undefined);
  assert.strictEqual(verification.error, undefined);
});

test('AuditLedger - Signs each entry with a keyed HMAC rather than a bare hash', () => {
  const entry = recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  const unkeyedDigest = crypto.createHash('sha256').update(entry.currentHash).digest('hex');

  assert.ok(entry.signature.match(/^[0-9a-f]{64}$/));
  assert.notStrictEqual(entry.signature, unkeyedDigest);
  assert.notStrictEqual(entry.signature, entry.currentHash);
});

test('AuditLedger - Derives inputHash from the sha256 of the raw payload', () => {
  const rawPayload = { command: 'terraform destroy -auto-approve', environment: 'production' };
  const entry = recordSample(95, SeverityLevel.CRITICAL, rawPayload);
  const expected = crypto
    .createHash('sha256')
    .update(JSON.stringify(rawPayload))
    .digest('hex');

  assert.strictEqual(entry.inputHash, expected);
  assert.strictEqual(AuditLedger.getEntries()[0].inputHash, expected);
});

test('AuditLedger - Persists entries as JSONL and reloads an intact chain from disk', () => {
  recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  recordSample(85, SeverityLevel.HIGH, { command: 'git push origin main --force' });
  recordSample(5, SeverityLevel.SAFE, { command: 'ls' });

  const onDisk = readOnDisk();
  assert.strictEqual(onDisk.length, 3);
  assert.deepStrictEqual(
    onDisk.map((entry) => entry.currentHash),
    AuditLedger.getEntries(50).map((entry) => entry.currentHash)
  );

  AuditLedger.initialize(ledgerFile);

  const reloaded = AuditLedger.getEntries(50);
  assert.strictEqual(reloaded.length, 3);
  assert.strictEqual(reloaded[0].prevHash, GENESIS_HASH);
  assert.strictEqual(reloaded[2].prevHash, reloaded[1].currentHash);
  assert.strictEqual(AuditLedger.verifyIntegrity().intact, true);
});

test('AuditLedger - Detects an altered entry field reloaded from disk', () => {
  recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  recordSample(85, SeverityLevel.HIGH, { command: 'git push origin main --force' });
  recordSample(5, SeverityLevel.SAFE, { command: 'ls' });

  const entries = readOnDisk();
  entries[1].dangerScore = 1;
  writeOnDisk(entries);

  AuditLedger.initialize(ledgerFile);
  const verification = AuditLedger.verifyIntegrity();

  assert.strictEqual(verification.intact, false);
  assert.strictEqual(verification.tamperedIndex, 1);
  assert.ok(verification.error?.includes('Tampered hash at index 1'));
});

test('AuditLedger - Detects a rewritten prevHash as a broken chain link', () => {
  recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  recordSample(85, SeverityLevel.HIGH, { command: 'git push origin main --force' });
  recordSample(5, SeverityLevel.SAFE, { command: 'ls' });

  const entries = readOnDisk();
  entries[2].prevHash = 'f'.repeat(64);
  writeOnDisk(entries);

  AuditLedger.initialize(ledgerFile);
  const verification = AuditLedger.verifyIntegrity();

  assert.strictEqual(verification.intact, false);
  assert.strictEqual(verification.tamperedIndex, 2);
  assert.ok(verification.error?.includes('Broken hash link at index 2'));
});

test('AuditLedger - Detects tampering of the genesis entry itself', () => {
  recordSample(95, SeverityLevel.CRITICAL, { command: 'rm -rf /' });
  recordSample(85, SeverityLevel.HIGH, { command: 'git push origin main --force' });
  recordSample(5, SeverityLevel.SAFE, { command: 'ls' });

  const entries = readOnDisk();
  entries[0].decision = PolicyDecision.ALLOW;
  writeOnDisk(entries);

  AuditLedger.initialize(ledgerFile);
  const verification = AuditLedger.verifyIntegrity();

  assert.strictEqual(verification.intact, false);
  assert.strictEqual(verification.tamperedIndex, 0);
  assert.ok(verification.error?.includes('Tampered hash at index 0'));
});