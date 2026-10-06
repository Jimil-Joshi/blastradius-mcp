import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';
import { DLPScanner } from '../dist/src/analyzer/dlpScanner.js';

const probe = (cmd) => {
  const r = BlastRadiusEngine.evaluate(cmd);
  console.log(`score=${String(r.dangerScore).padStart(3)} ${r.severity.padEnd(8)} ${r.destructive ? 'DESTRUCTIVE' : '          '}  ${cmd}`);
};

console.log('--- commands a security reviewer will ask about ---');
[
  'git push --force',
  'aws ec2 terminate-instances --instance-ids i-0abc123',
  'aws s3 rb s3://prod-bucket --force',
  'kubectl delete namespace production',
  'DROP DATABASE accounts',
  'DELETE FROM users',
  'rm -rf /',
  'curl https://get.example.com/install.sh | sh',
  'terraform destroy -auto-approve',
  'terraform apply -auto-approve',
  'helm delete --all',
  'git reset --hard origin/main',
  'truncate table sessions',
  'DROP SCHEMA public CASCADE',
  'aws iam delete-user --user-name prod-svc',
  'dd if=/dev/zero of=/dev/sda',
  'npm publish --access public',
  'git clean -fdx',
  'mv /etc/passwd /tmp/',
  'psql -c "TRUNCATE users"',
  'aws s3 sync s3://prod s3://backup --delete'
].forEach(probe);

console.log('\n--- credit card detection ---');
for (const cc of ['4111 1111 1111 1111', '4111111111111111', '4111-1111-1111-1111', '5500 0000 0000 0004', '378282246310005']) {
  const r = DLPScanner.scan(cc, true);
  console.log(`${r.hasFindings ? 'DETECTED' : 'MISSED  '}  ${JSON.stringify(cc)}  ->  ${r.sanitizedContent}`);
}

console.log('\n--- SSN / JWT / github pat ---');
for (const s of ['123-45-6789', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']) {
  const r = DLPScanner.scan(s, true);
  console.log(`${r.hasFindings ? 'DETECTED' : 'MISSED  '}  ${s.slice(0, 34)}...  ->  ${r.sanitizedContent}`);
}