import test, { after, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SequenceDetector, SequenceSignal } from '../src/analyzer/sequenceDetector.js';
import { AuditLedger } from '../src/security/auditLedger.js';
import {
  ActionCategory,
  AuditEntry,
  PolicyDecision,
  SecurityPolicyConfig,
  SeverityLevel
} from '../src/types.js';

const GENESIS_HASH = '0'.repeat(64);
const BASE_TIME = Date.parse('2026-09-01T00:00:00.000Z');

let counter = 0;

interface EntrySpec {
  toolName: string;
  category?: ActionCategory;
  decision?: PolicyDecision;
  severity?: SeverityLevel;
  dangerScore?: number;
  reasons?: string[];
  dlpFindingsCount?: number;
  callerId?: string;
  inputHash?: string;
  index?: number;
  timestampOffsetSeconds?: number;
}

/**
 * Synthetic ledger entry. Fields the real AuditLedger would fill in from the
 * hash chain are stubbed, because the detector never reads them.
 */
function entry(spec: EntrySpec): AuditEntry {
  const index = spec.index ?? counter++;
  const offset = spec.timestampOffsetSeconds ?? index;
  return {
    index,
    timestamp: new Date(BASE_TIME + offset * 1000).toISOString(),
    toolName: spec.toolName,
    callerId: spec.callerId ?? 'agent-client',
    category: spec.category ?? ActionCategory.SHELL,
    decision: spec.decision ?? PolicyDecision.ALLOW,
    dangerScore: spec.dangerScore ?? 5,
    severity: spec.severity ?? SeverityLevel.SAFE,
    reasons: spec.reasons ?? ['Standard read-only or low-impact routine action.'],
    dlpFindingsCount: spec.dlpFindingsCount ?? 0,
    inputHash: spec.inputHash ?? `hash-${index}`,
    prevHash: GENESIS_HASH,
    currentHash: 'a'.repeat(64),
    signature: 'b'.repeat(64)
  };
}

const ROUTINE_READ = ['Standard read-only or low-impact routine action.'];
const CLOUD_TERMINATION = [
  'Cloud resource termination (EC2, RDS, S3, or EKS) will destroy infrastructure'
];
const CREDENTIAL_ACCESS = [
  'Direct access or modification to sensitive credentials or system auth files'
];
const TERRAFORM_TEARDOWN = [
  'Infrastructure-as-code teardown or unattended apply can destroy every managed resource in one command'
];
const STEP_UP_REQUIRED = (severity: SeverityLevel, score: number) => [
  `Elevated risk (Severity: ${severity}, Danger Score: ${score}). Cryptographic confirmation token required to proceed.`
];

function destroyBucket(): AuditEntry {
  return entry({
    toolName: 'aws_s3_delete_bucket',
    category: ActionCategory.CLOUD,
    decision: PolicyDecision.REQUIRE_CONFIRMATION,
    severity: SeverityLevel.CRITICAL,
    dangerScore: 95,
    reasons: CLOUD_TERMINATION
  });
}

function signalFor(analysis: { signals: SequenceSignal[] }, id: SequenceSignal['id']): SequenceSignal | undefined {
  return analysis.signals.find((signal) => signal.id === id);
}

beforeEach(() => {
  counter = 0;
});

test('SequenceDetector - Flags a credential read immediately followed by a destructive call', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({
      toolName: 'read_config',
      category: ActionCategory.FILESYSTEM,
      dangerScore: 40,
      severity: SeverityLevel.LOW,
      dlpFindingsCount: 2,
      reasons: ['Standard read-only or low-impact routine action.']
    }),
    destroyBucket()
  ];

  const analysis = detector.analyze(entries);
  const signal = signalFor(analysis, 'exfiltration-then-destruction');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.CRITICAL);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_BLOCK');
  assert.deepStrictEqual(signal.evidence.fromIndex, 0);
  assert.deepStrictEqual(signal.evidence.toIndex, 1);
  assert.strictEqual(signal.evidence.decisionCount, 2);
  assert.deepStrictEqual(signal.evidence.toolNames, ['read_config', 'aws_s3_delete_bucket']);
  assert.ok(signal.reason.includes('index 0'), signal.reason);
  assert.ok(signal.reason.includes('index 1'), signal.reason);
  assert.ok(signal.confidence > 0.8 && signal.confidence <= 0.95, String(signal.confidence));
});

test('SequenceDetector - Flags credential-file access followed by an IaC teardown at HIGH severity', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({
      toolName: 'read_file',
      category: ActionCategory.FILESYSTEM,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      severity: SeverityLevel.HIGH,
      dangerScore: 80,
      reasons: CREDENTIAL_ACCESS
    }),
    entry({
      toolName: 'terraform',
      category: ActionCategory.CLOUD,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      severity: SeverityLevel.HIGH,
      dangerScore: 95,
      reasons: TERRAFORM_TEARDOWN
    })
  ];

  const signal = signalFor(detector.analyze(entries), 'exfiltration-then-destruction');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_CONFIRMATION');
  assert.deepStrictEqual(signal.evidence.toolNames, ['read_file', 'terraform']);
});

test('SequenceDetector - Does not flag destruction that has no preceding credential read', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'list_files', category: ActionCategory.FILESYSTEM, reasons: ROUTINE_READ }),
    entry({ toolName: 'list_tables', category: ActionCategory.SQL, reasons: ROUTINE_READ }),
    destroyBucket()
  ];

  const analysis = detector.analyze(entries);

  assert.strictEqual(signalFor(analysis, 'exfiltration-then-destruction'), undefined);
  assert.strictEqual(analysis.highestSeverity, SeverityLevel.SAFE);
  assert.strictEqual(analysis.analysedEntries, 3);
  assert.strictEqual(analysis.truncated, false);
});

test('SequenceDetector - Requires the credential read to precede the destruction', () => {
  const detector = new SequenceDetector();
  const entries = [
    destroyBucket(),
    entry({
      toolName: 'read_file',
      category: ActionCategory.FILESYSTEM,
      severity: SeverityLevel.HIGH,
      dangerScore: 80,
      reasons: CREDENTIAL_ACCESS
    })
  ];

  // Ordering is the whole claim. A read that lands after the destroy is cleanup.
  assert.strictEqual(signalFor(detector.analyze(entries), 'exfiltration-then-destruction'), undefined);
});

test('SequenceDetector - Flags a multi-resource read run followed by a network call', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'list_files', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'list_files', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL }),
    entry({
      toolName: 'list_buckets',
      category: ActionCategory.CLOUD,
      severity: SeverityLevel.LOW,
      dangerScore: 20
    }),
    entry({
      toolName: 'send_webhook',
      category: ActionCategory.NETWORK,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 60,
      reasons: ['Outbound HTTP transfer to a remote endpoint']
    })
  ];

  const signal = signalFor(detector.analyze(entries), 'reconnaissance-then-exfiltration');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.MEDIUM);
  assert.strictEqual(signal.recommendedAction, 'FLAG_FOR_REVIEW');
  assert.deepStrictEqual(signal.evidence.fromIndex, 0);
  assert.deepStrictEqual(signal.evidence.toIndex, 6);
  assert.strictEqual(signal.evidence.decisionCount, 7);
  assert.ok(signal.reason.includes('index 0') && signal.reason.includes('index 6'), signal.reason);
});

test('SequenceDetector - Raises the recon signal to HIGH when the sink carries DLP findings', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL }),
    entry({
      toolName: 'upload_archive',
      category: ActionCategory.NETWORK,
      severity: SeverityLevel.HIGH,
      dangerScore: 75,
      dlpFindingsCount: 4,
      reasons: ['Outbound upload of a staged payload']
    })
  ];

  const signal = signalFor(detector.analyze(entries), 'reconnaissance-then-exfiltration');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_CONFIRMATION');
});

test('SequenceDetector - Does not flag a short read run followed by a network call', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM }),
    entry({
      toolName: 'send_webhook',
      category: ActionCategory.NETWORK,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 60,
      reasons: ['Outbound HTTP transfer to a remote endpoint']
    })
  ];

  assert.strictEqual(
    signalFor(detector.analyze(entries), 'reconnaissance-then-exfiltration'),
    undefined
  );
});

test('SequenceDetector - Flags a privilege ladder of distinct operations at non-decreasing severity', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({
      toolName: 'postgres_query',
      category: ActionCategory.SQL,
      decision: PolicyDecision.ALLOW,
      severity: SeverityLevel.HIGH,
      dangerScore: 80,
      reasons: ['Excessive database privilege grant (GRANT ALL PRIVILEGES) violates least privilege']
    }),
    entry({
      toolName: 'iam_create_user',
      category: ActionCategory.CLOUD,
      decision: PolicyDecision.ALLOW,
      severity: SeverityLevel.HIGH,
      dangerScore: 85,
      reasons: ['Cloud IAM identity creation for a new principal']
    }),
    entry({
      toolName: 'iam_attach_role',
      category: ActionCategory.CLOUD,
      decision: PolicyDecision.ALLOW,
      severity: SeverityLevel.HIGH,
      dangerScore: 90,
      reasons: ['Role binding granted to a live principal']
    })
  ];

  const signal = signalFor(detector.analyze(entries), 'privilege-ladder');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_CONFIRMATION');
  assert.strictEqual(signal.evidence.decisionCount, 3);
  assert.ok(signal.reason.includes('grant-all'), signal.reason);
  assert.ok(signal.reason.includes('create-identity'), signal.reason);
  assert.ok(signal.reason.includes('attach-role'), signal.reason);
});

test('SequenceDetector - Flags one tool called repeatedly with strictly rising danger scores', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'cloud_api_call', category: ActionCategory.CLOUD, dangerScore: 10, severity: SeverityLevel.LOW }),
    entry({ toolName: 'cloud_api_call', category: ActionCategory.CLOUD, dangerScore: 55, severity: SeverityLevel.MEDIUM }),
    entry({ toolName: 'cloud_api_call', category: ActionCategory.CLOUD, dangerScore: 92, severity: SeverityLevel.HIGH })
  ];

  const signal = signalFor(detector.analyze(entries), 'privilege-ladder');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.deepStrictEqual(signal.evidence.toolNames, ['cloud_api_call']);
  assert.strictEqual(signal.evidence.decisionCount, 3);
  assert.ok(signal.reason.includes('strictly rising dangerScore'), signal.reason);
});

test('SequenceDetector - Does not flag privilege operations that ratchet back down', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({
      toolName: 'postgres_query',
      category: ActionCategory.SQL,
      severity: SeverityLevel.HIGH,
      dangerScore: 80,
      reasons: ['Excessive database privilege grant (GRANT ALL PRIVILEGES) violates least privilege']
    }),
    entry({
      toolName: 'iam_create_user',
      category: ActionCategory.CLOUD,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 50,
      reasons: ['Cloud IAM identity creation for a new principal']
    }),
    entry({
      toolName: 'iam_attach_role',
      category: ActionCategory.CLOUD,
      severity: SeverityLevel.SAFE,
      dangerScore: 10,
      reasons: ['Role binding granted to a live principal']
    })
  ];

  assert.strictEqual(signalFor(detector.analyze(entries), 'privilege-ladder'), undefined);
});

test('SequenceDetector - Does not call a rising read run an escalating ladder', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'db_query', category: ActionCategory.SQL, dangerScore: 5, severity: SeverityLevel.SAFE }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL, dangerScore: 10, severity: SeverityLevel.SAFE }),
    entry({ toolName: 'db_query', category: ActionCategory.SQL, dangerScore: 20, severity: SeverityLevel.SAFE })
  ];

  assert.strictEqual(signalFor(detector.analyze(entries), 'privilege-ladder'), undefined);
});

test('SequenceDetector - Flags three refusals against one tool family', () => {
  const detector = new SequenceDetector();
  const refusal = (index: number) =>
    entry({
      toolName: 'delete_records',
      category: ActionCategory.SQL,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 45,
      reasons: STEP_UP_REQUIRED(SeverityLevel.MEDIUM, 45),
      index
    });

  const signal = signalFor(detector.analyze([refusal(0), refusal(1), refusal(2)]), 'guardrail-probing');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.MEDIUM);
  assert.strictEqual(signal.recommendedAction, 'FLAG_FOR_REVIEW');
  assert.strictEqual(signal.evidence.decisionCount, 3);
  assert.ok(signal.reason.includes("'delete'"), signal.reason);
});

test('SequenceDetector - Raises a probing signal to HIGH once a refusal is a hard block', () => {
  const detector = new SequenceDetector();
  const refusal = (index: number, decision: PolicyDecision) =>
    entry({
      toolName: 'delete_records',
      category: ActionCategory.SQL,
      decision,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 45,
      reasons: STEP_UP_REQUIRED(SeverityLevel.MEDIUM, 45),
      index
    });

  const entries = [
    refusal(0, PolicyDecision.REQUIRE_CONFIRMATION),
    refusal(1, PolicyDecision.BLOCK),
    refusal(2, PolicyDecision.REQUIRE_CONFIRMATION),
    refusal(3, PolicyDecision.BLOCK)
  ];

  const signal = signalFor(detector.analyze(entries), 'guardrail-probing');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_CONFIRMATION');
  assert.ok(signal.reason.includes('2 BLOCK'), signal.reason);
});

test('SequenceDetector - Does not flag two refusals against the same tool', () => {
  const detector = new SequenceDetector();
  const refusal = (index: number) =>
    entry({
      toolName: 'delete_records',
      category: ActionCategory.SQL,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 45,
      reasons: STEP_UP_REQUIRED(SeverityLevel.MEDIUM, 45),
      index
    });

  assert.strictEqual(
    signalFor(detector.analyze([refusal(0), refusal(1)]), 'guardrail-probing'),
    undefined
  );
});

test('SequenceDetector - Flags a burst of four destructive decisions inside one window', () => {
  const detector = new SequenceDetector();
  const entries: AuditEntry[] = [];
  for (let i = 0; i < 8; i++) {
    entries.push(
      i % 2 === 1
        ? entry({
            toolName: `aws_delete_${i}`,
            category: ActionCategory.CLOUD,
            severity: SeverityLevel.CRITICAL,
            dangerScore: 95,
            reasons: CLOUD_TERMINATION
          })
        : entry({ toolName: `list_${i}`, category: ActionCategory.CLOUD, severity: SeverityLevel.LOW, dangerScore: 20 })
    );
  }

  const signal = signalFor(detector.analyze(entries), 'destructive-burst');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.HIGH);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_CONFIRMATION');
  assert.strictEqual(signal.evidence.decisionCount, 4);
  assert.deepStrictEqual(signal.evidence.fromIndex, 1);
  assert.deepStrictEqual(signal.evidence.toIndex, 7);
  assert.ok(signal.reason.includes('speed, not history'), signal.reason);
});

test('SequenceDetector - Escalates a burst to CRITICAL once six destructive decisions cluster', () => {
  const detector = new SequenceDetector();
  const entries: AuditEntry[] = [];
  for (let i = 0; i < 8; i++) {
    entries.push(
      i < 6
        ? entry({
            toolName: `aws_delete_${i}`,
            category: ActionCategory.CLOUD,
            severity: SeverityLevel.CRITICAL,
            dangerScore: 95,
            reasons: CLOUD_TERMINATION
          })
        : entry({ toolName: `list_${i}`, category: ActionCategory.CLOUD, severity: SeverityLevel.LOW, dangerScore: 20 })
    );
  }

  const signal = signalFor(detector.analyze(entries), 'destructive-burst');

  assert.ok(signal);
  assert.strictEqual(signal.severity, SeverityLevel.CRITICAL);
  assert.strictEqual(signal.recommendedAction, 'ESCALATE_TO_BLOCK');
  assert.strictEqual(signal.evidence.decisionCount, 6);
});

test('SequenceDetector - Does not flag three destructive decisions as a burst', () => {
  const detector = new SequenceDetector();
  const entries: AuditEntry[] = [];
  for (let i = 0; i < 10; i++) {
    entries.push(
      i === 1 || i === 5 || i === 9
        ? entry({
            toolName: `aws_delete_${i}`,
            category: ActionCategory.CLOUD,
            severity: SeverityLevel.CRITICAL,
            dangerScore: 95,
            reasons: CLOUD_TERMINATION
          })
        : entry({ toolName: `list_${i}`, category: ActionCategory.CLOUD, severity: SeverityLevel.LOW, dangerScore: 20 })
    );
  }

  assert.strictEqual(signalFor(detector.analyze(entries), 'destructive-burst'), undefined);
});

test('SequenceDetector - Reports truncation when the analysed window starts mid-history', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM, severity: SeverityLevel.HIGH, dangerScore: 80, reasons: CREDENTIAL_ACCESS }),
    destroyBucket(),
    ...Array.from({ length: 10 }, (_unused, i) =>
      entry({ toolName: `list_${i}`, category: ActionCategory.FILESYSTEM, index: i + 2 })
    )
  ];

  const truncated = detector.analyze(entries, { windowSize: 5 });

  assert.strictEqual(truncated.truncated, true);
  assert.strictEqual(truncated.analysedEntries, 5);
  assert.strictEqual(
    signalFor(truncated, 'exfiltration-then-destruction'),
    undefined,
    'the pattern began before the window, so the detector must not claim to have cleared it'
  );

  const whole = detector.analyze(entries);

  assert.strictEqual(whole.truncated, false);
  assert.strictEqual(whole.analysedEntries, 12);
  assert.ok(signalFor(whole, 'exfiltration-then-destruction'));
});

test('SequenceDetector - Flags a windowed history that starts after index zero', () => {
  const detector = new SequenceDetector();
  const entries = [
    entry({ toolName: 'delete_records', category: ActionCategory.SQL, decision: PolicyDecision.BLOCK, index: 480 }),
    entry({ toolName: 'delete_records', category: ActionCategory.SQL, decision: PolicyDecision.BLOCK, index: 481 }),
    entry({ toolName: 'delete_records', category: ActionCategory.SQL, decision: PolicyDecision.BLOCK, index: 482 })
  ];

  const analysis = detector.analyze(entries);

  assert.strictEqual(analysis.truncated, true);
  assert.ok(signalFor(analysis, 'guardrail-probing'));
});

test('SequenceDetector - Reads the live ledger without disturbing its hash chain', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-sequence-'));
  const ledgerFile = path.join(tmpDir, 'blastradius-audit.jsonl');

  try {
    AuditLedger.initialize(ledgerFile);

    AuditLedger.record({
      toolName: 'read_file',
      callerId: 'agent-client',
      category: ActionCategory.FILESYSTEM,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      dangerScore: 80,
      severity: SeverityLevel.HIGH,
      reasons: CREDENTIAL_ACCESS,
      dlpFindingsCount: 0,
      rawPayload: { path: '/app/.env' }
    });
    AuditLedger.record({
      toolName: 'aws_s3_delete_bucket',
      callerId: 'agent-client',
      category: ActionCategory.CLOUD,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      dangerScore: 95,
      severity: SeverityLevel.CRITICAL,
      reasons: CLOUD_TERMINATION,
      dlpFindingsCount: 0,
      rawPayload: { bucket: 'prod-artifacts' }
    });

    const analysis = new SequenceDetector().analyzeFromLedger();
    const signal = signalFor(analysis, 'exfiltration-then-destruction');

    assert.ok(signal);
    assert.strictEqual(signal.evidence.fromIndex, 0);
    assert.strictEqual(signal.evidence.toIndex, 1);
    assert.strictEqual(analysis.analysedEntries, 2);
    assert.strictEqual(analysis.truncated, false);
    assert.strictEqual(AuditLedger.verifyIntegrity().intact, true);
  } finally {
    AuditLedger.reset();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SequenceDetector - Obeys the policy config for disabling and for thresholds', () => {
  const policy: SecurityPolicyConfig = {
    version: '1.0.0',
    name: 'sequence-test',
    description: 'Sequence detector configuration test',
    defaultDecision: PolicyDecision.ALLOW,
    rules: []
  };

  const entries = [
    entry({ toolName: 'read_file', category: ActionCategory.FILESYSTEM, severity: SeverityLevel.HIGH, dangerScore: 80, reasons: CREDENTIAL_ACCESS }),
    destroyBucket()
  ];

  const disabled = SequenceDetector.fromPolicy({ ...policy, sequence: { enabled: false } }).analyze(entries);

  assert.deepStrictEqual(disabled.signals, []);
  assert.strictEqual(disabled.highestSeverity, SeverityLevel.SAFE);
  assert.strictEqual(disabled.analysedEntries, 0);

  const refusal = (index: number) =>
    entry({
      toolName: 'delete_records',
      category: ActionCategory.SQL,
      decision: PolicyDecision.REQUIRE_CONFIRMATION,
      severity: SeverityLevel.MEDIUM,
      dangerScore: 45,
      reasons: STEP_UP_REQUIRED(SeverityLevel.MEDIUM, 45),
      index
    });

  const tuned = SequenceDetector.fromPolicy({ ...policy, sequence: { windowSize: 4, probingThreshold: 2 } });
  const tunedAnalysis = tuned.analyze([refusal(0), refusal(1)]);

  assert.ok(signalFor(tunedAnalysis, 'guardrail-probing'), 'probingThreshold: 2 must lower the bar');

  const long = tuned.analyze([
    ...entries,
    ...Array.from({ length: 10 }, (_unused, i) => entry({ toolName: `list_${i}`, index: i + 2 }))
  ]);

  assert.strictEqual(long.truncated, true, 'windowSize: 4 must truncate a 12-entry history');
  assert.strictEqual(long.analysedEntries, 4);
});