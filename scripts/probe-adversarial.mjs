// Adversarial probe: every case raised by the persona review, plus the
// false-positive cases that review correctly predicted we never tested.
import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';
import { ShellResolver } from '../dist/src/analyzer/shellResolver.js';
import { PolicyEngine } from '../dist/src/policy/policyEngine.js';

const DANGEROUS = [
  ['brace expansion', 'rm -rf /{etc,var,home}'],
  ['nested substitution', 'echo $(echo $(date)) && rm -rf /'],
  ['multi-line script', 'cd /tmp\necho preparing\nrm -rf /'],
  ['multi-line via &&', 'cd /tmp && rm -rf /\nwhoami'],
  ['quoted variable path traversal', 'cd /tmp && T=../.. && rm -rf "$T"'],
  ['variable hiding secret path', 'D=/etc; cat $D/shadow'],
  ['variable hiding protected file', 'P=/root; cat $P/.env'],
  ['rsync mass delete', 'rsync -a --delete /srv/data/ /backup/'],
  ['docker prune', 'docker system prune -af'],
  ['redis flushall', 'redis-cli FLUSHALL'],
  ['aws s3 rm recursive', 'aws s3 rm s3://prod-logs --recursive'],
  ['base64 decode pipe', 'echo cm0gLXJmIC8= | base64 -d | sh']
];

const BENIGN = [
  ['ordinary var scripting', 'TARGET=$PWD/build; rm -rf $TARGET'],
  ['ordinary var non-root', 'D=/var/tmp/cache; rm -rf $D'],
  ['unresolved benign var', 'rm -rf $CACHE_DIR'],
  ['quoted path with spaces', 'rm -rf "my important dir"'],
  ['rsync without delete', 'rsync -a /src/ /dst/'],
  ['quoted brace literal', "echo '{a,b}'"]
];

console.log('=== ATTACKS (want >= 70) ===');
for (const [label, cmd] of DANGEROUS) {
  const r = BlastRadiusEngine.evaluate(cmd);
  const ok = r.dangerScore >= 70;
  console.log(`${ok ? 'CAUGHT ' : 'MISSED '} ${String(r.dangerScore).padStart(3)} ${r.severity.padEnd(8)} [${label}] ${JSON.stringify(cmd)}`);
  if (!ok) console.log(`          resolved: ${r.resolution?.resolvedCommand}`);
}

console.log('\n=== BENIGN (want < 70) ===');
let fp = 0;
for (const [label, cmd] of BENIGN) {
  const r = BlastRadiusEngine.evaluate(cmd);
  const bad = r.dangerScore >= 70;
  if (bad) fp++;
  console.log(`${bad ? 'OVERBLOCK' : 'ok      '} ${String(r.dangerScore).padStart(3)} ${r.severity.padEnd(8)} [${label}] ${JSON.stringify(cmd)}`);
}

console.log('\n=== ZT-004 must resolve through the shell layer ===');
const engine = new PolicyEngine();
for (const cmd of [
  'cat /etc/shadow',
  'D=/etc; cat $D/shadow',            // literal is absent from the request
  'D=/root; cat $D/.env',
  'P=$(echo .env); cat $P'
]) {
  const res = engine.evaluate('bash', { command: cmd }, BlastRadiusEngine.evaluate(cmd));
  console.log(`${res.decision === 'BLOCK' ? 'BLOCKED ' : 'PASSED  '} ${JSON.stringify(cmd)}  -> ${res.decision} (${res.ruleMatched})`);
}

console.log('\n=== resolver specifics ===');
for (const cmd of ['rm -rf /{etc,var,home}', 'rm -rf "my important dir"', 'echo $(echo $(date))', 'a\nrm -rf /']) {
  const res = ShellResolver.resolve(cmd);
  console.log(`${JSON.stringify(cmd)} -> ${JSON.stringify(res.resolved)}`);
}

console.log(`\nfalse positives: ${fp}/${BENIGN.length}`);