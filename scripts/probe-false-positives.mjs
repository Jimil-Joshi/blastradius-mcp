// False-positive probe. A guardrail that blocks everything is not a guardrail;
// if safe commands are being scored HIGH, the rules are too coarse to ship.
import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';

const BENIGN = [
  'ls -la',
  'pwd',
  'cat README.md',
  'grep -r "TODO" src/',
  'npm install',
  'npm run build',
  'npm test',
  'git status',
  'git add .',
  'git commit -m "fix: handle empty input"',
  'git push origin feature/login',
  'git push --force-with-lease',
  'git checkout -b feature/x',
  'docker build -t app:latest .',
  'docker ps',
  'kubectl get pods -n production',
  'kubectl logs -f deploy/api',
  'terraform plan',
  'terraform fmt',
  'kubectl apply -f deployment.yaml',
  'helm list',
  'SELECT id, email FROM users LIMIT 10',
  'SELECT COUNT(*) FROM orders WHERE status = $1',
  'UPDATE users SET last_login = now() WHERE id = $1',
  'INSERT INTO events (type, payload) VALUES ($1, $2)',
  'curl -s https://api.example.com/health',
  'wget https://example.com/file.txt',
  'tar -czf backup.tar.gz ./dist',
  'rsync -av ./build ./dist',
  'rm -rf node_modules',
  'rm -rf ./build',
  'rm -f /tmp/scratch.log',
  'rm /tmp/oldfile.txt',
  'mkdir -p src/new',
  'chmod +x scripts/run.sh',
  'psql -c "SELECT 1"',
  'make clean',
  'yarn install --frozen-lockfile',
  'pip install -r requirements.txt'
];

console.log('=== FALSE POSITIVES (should all be under 70) ===');
let falsePositives = 0;
for (const cmd of BENIGN) {
  const r = BlastRadiusEngine.evaluate(cmd);
  const bad = r.dangerScore >= 70;
  if (bad) falsePositives++;
  console.log(
    `${bad ? 'OVERBLOCK ' : 'ok       '} ${String(r.dangerScore).padStart(3)} ${r.severity.padEnd(8)} ${cmd}`
  );
  if (bad) console.log(`           via: ${r.reasons.join(' | ')}`);
}
console.log(`\n${BENIGN.length - falsePositives}/${BENIGN.length} benign commands correctly scored below HIGH`);
