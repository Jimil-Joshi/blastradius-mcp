// Generates the README transcripts from the real engine, so no example in the
// README is hand-written. Run: npm run build && node scripts/generate-readme-transcripts.mjs
import { BlastRadiusEngine } from '../dist/src/analyzer/blastRadiusEngine.js';
import { DLPScanner } from '../dist/src/analyzer/dlpScanner.js';
import { PolicyEngine } from '../dist/src/policy/policyEngine.js';
import { TokenManager } from '../dist/src/security/tokenManager.js';

const out = (label, value) => {
  console.log(`\n##### ${label}`);
  console.log(JSON.stringify(value, null, 2));
};

// --- 1. Scoring a destructive action -----------------------------------------
out('simulate_action("rm -rf / --no-preserve-root")', BlastRadiusEngine.evaluate('rm -rf / --no-preserve-root'));

// --- 2. The same command, different environment ------------------------------
out(
  'simulate_action("aws s3 rb s3://prod-bucket --force", context={environment:"production"})',
  BlastRadiusEngine.evaluate('aws s3 rb s3://prod-bucket --force', undefined, {
    environment: 'production'
  })
);

// --- 3. A read is not a risk --------------------------------------------------
out('simulate_action("SELECT id, email FROM users LIMIT 10")', BlastRadiusEngine.evaluate('SELECT id, email FROM users LIMIT 10'));

// --- 4. DLP ------------------------------------------------------------------
out(
  'inspect_payload_dlp(<log line with an AWS key, a DB password and a card>)',
  DLPScanner.scan(
    JSON.stringify({
      authorization: 'Bearer AKIAIOSFODNN7EXAMPLE',
      dsn: 'postgres://admin:hunter2@db.internal:5432/prod',
      card: '4111 1111 1111 1111',
      note: 'owner joe@acme.com'
    }),
    true
  )
);

// --- 5. The policy gate ------------------------------------------------------
const engine = new PolicyEngine();
out(
  'enforce_policy("bash", {command: "rm -rf /var/lib/postgresql"})  -> BLOCKED',
  engine.evaluate('bash', { command: 'rm -rf /var/lib/postgresql' }, BlastRadiusEngine.evaluate('rm -rf /var/lib/postgresql'))
);

// --- 6. Step-up approval, then replay ----------------------------------------
const destroy = BlastRadiusEngine.evaluate('terraform destroy -auto-approve');
out(
  'enforce_policy("bash", {command: "terraform destroy -auto-approve"})  -> needs a token',
  engine.evaluate('bash', { command: 'terraform destroy -auto-approve' }, destroy)
);

const approval = TokenManager.generateToken(
  'bash',
  `${destroy.dangerScore}:terraform-destroy`,
  'jimil@acme.dev',
  300,
  'Approved in ticket OPS-4471'
);
out('request_confirmation_token(...).payload', approval.payload);

out(
  'enforce_policy(..., confirmationToken)  -> ALLOW, token burned',
  engine.evaluate('bash', { command: 'terraform destroy -auto-approve' }, destroy, approval.token)
);

out(
  'enforce_policy(..., same token again)  -> refused',
  engine.evaluate('bash', { command: 'terraform destroy -auto-approve' }, destroy, approval.token)
);