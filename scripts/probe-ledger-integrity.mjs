import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.BLAST_RADIUS_AUDIT_KEY = 'stable-test-key-for-verification-only';

async function freshLedger(count) {
  const tmp = mkdtempSync(join(tmpdir(), 'br-trunc-'));
  const file = join(tmp, 'audit.jsonl');
  process.env.BLAST_RADIUS_AUDIT_PATH = file;
  const mod = await import(`../dist/src/security/auditLedger.js?bust=${Math.random()}`);
  const { SeverityLevel, ActionCategory, PolicyDecision } = await import('../dist/src/types.js');
  mod.AuditLedger.initialize(file);
  for (let i = 0; i < count; i++) {
    mod.AuditLedger.record({
      toolName: `tool_${i}`,
      callerId: 'agent',
      category: ActionCategory.SHELL,
      decision: i === count - 1 ? PolicyDecision.BLOCK : PolicyDecision.ALLOW,
      dangerScore: i === count - 1 ? 100 : 5,
      severity: i === count - 1 ? SeverityLevel.CRITICAL : SeverityLevel.SAFE,
      reasons: i === count - 1 ? ['Recursive root deletion detected'] : ['routine'],
      dlpFindingsCount: i === count - 1 ? 3 : 0,
      rawPayload: { i }
    });
  }
  return { mod, file, tmp };
}

// --- clean baseline ---
{
  const { mod, file, tmp } = await freshLedger(10);
  console.log('clean        :', JSON.stringify(mod.AuditLedger.verifyIntegrity(500)));
  rmSync(tmp, { recursive: true, force: true });
}

// --- tail truncation only, nothing else rewritten ---
{
  const { mod, file, tmp } = await freshLedger(10);
  const lines = readFileSync(file, 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
  console.log('before       :', lines.length, 'entries, last decision =', lines[9].decision);
  // Drop the last four, including the BLOCK that the attacker wanted hidden.
  writeFileSync(file, lines.slice(0, 6).map((l) => JSON.stringify(l)).join('\n') + '\n');
  const mod2 = (await import(`../dist/src/security/auditLedger.js?b2=${Math.random()}`));
  mod2.AuditLedger.initialize(file);
  const r = mod2.AuditLedger.verifyIntegrity(500);
  console.log('after cut    :', JSON.stringify(r));
  rmSync(tmp, { recursive: true, force: true });
}

// --- head truncation (deleting from the beginning) ---
{
  const { mod, file, tmp } = await freshLedger(10);
  const lines = readFileSync(file, 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
  writeFileSync(file, lines.slice(3).map((l) => JSON.stringify(l)).join('\n') + '\n');
  const mod2 = (await import(`../dist/src/security/auditLedger.js?b3=${Math.random()}`));
  mod2.AuditLedger.initialize(file);
  console.log('head cut     :', JSON.stringify(mod2.AuditLedger.verifyIntegrity(500)));
  rmSync(tmp, { recursive: true, force: true });
}

// --- middle deletion ---
{
  const { mod, file, tmp } = await freshLedger(10);
  const lines = readFileSync(file, 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
  writeFileSync(file, [...lines.slice(0, 4), ...lines.slice(6)].map((l) => JSON.stringify(l)).join('\n') + '\n');
  const mod2 = (await import(`../dist/src/security/auditLedger.js?b4=${Math.random()}`));
  mod2.AuditLedger.initialize(file);
  console.log('middle cut   :', JSON.stringify(mod2.AuditLedger.verifyIntegrity(500)));
  rmSync(tmp, { recursive: true, force: true });
}