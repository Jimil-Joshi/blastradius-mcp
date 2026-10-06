import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';
import { PolicyEngine } from '../dist/src/policy/policyEngine.js';

const eng = new PolicyEngine();

const cases = [
  ['structured argv', { command: 'rm', args: ['-rf', '/'] }],
  ['structured argv shallow', { tool: 'exec', parameters: { command: 'DROP TABLE users' } }],
  ['nested argv', { action: { program: 'sh', arguments: ['-c', 'rm -rf /'] } }],
  ['plain string', { command: 'rm -rf /' }],
  ['secret via argv', { command: 'cat', args: ['/etc/shadow'] }],
  ['safe argv', { command: 'ls', args: ['-la'] }],
  ['safe git', { command: 'git', args: ['status'] }]
];

console.log('=== end-to-end: engine score vs policy decision ===');
for (const [label, params] of cases) {
  // enforce_policy stringifies params before calling the engine, so do the same.
  const report = BlastRadiusEngine.evaluate(JSON.stringify(params));
  const policy = eng.evaluate('bash', params, report);
  const blocked = policy.decision === 'BLOCK';
  const critical = report.dangerScore >= 90;
  const gap = critical && !blocked;
  console.log(
    `${gap ? 'GAP!! ' : 'ok    '} score=${String(report.dangerScore).padStart(3)} ${report.severity.padEnd(8)} ${policy.decision.padEnd(19)} ${label}`
  );
}