import { performance } from 'node:perf_hooks';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { SemanticRouter } from '../src/gateway/semanticRouter.js';
import { ContextVirtualizer } from '../src/gateway/contextVirtualizer.js';
import { SwarmNativeEngine } from '../src/swarm/nativeEngine.js';
import {
  createHackerPersona,
  createConfusedUserPersona,
  createLegacySystemPersona,
  createConcurrencyRacerPersona,
  createDataCorruptorPersona
} from '../src/swarm/personas/index.js';
import { generateHeatmap } from '../src/swarm/heatmapGenerator.js';
import { BlastRadiusEngine } from '../src/analyzer/blastRadiusEngine.js';
import { TddStateMachine } from '../src/quality/tddStateMachine.js';
import { critiqueCode } from '../src/quality/codeCritique.js';
import { TokenManager } from '../src/security/tokenManager.js';
import { AuditLedger } from '../src/security/auditLedger.js';
import { DataFlywheel } from '../src/storage/flywheel.js';
import { TddPhase, SeverityLevel, ActionCategory, PolicyDecision } from '../src/types.js';

interface PillarTestResult {
  pillar: string;
  testName: string;
  claimedParameter: string;
  measuredResult: string;
  passed: boolean;
  notes?: string;
}

const results: PillarTestResult[] = [];

function record(res: PillarTestResult) {
  results.push(res);
  const mark = res.passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${mark} [${res.pillar}] ${res.testName}: ${res.measuredResult}`);
}

async function runEvaluation() {
  console.log('================================================================');
  console.log('   BLASTRADIUS 2.0 EMPIRICAL 4-PILLAR EVALUATION HARNESS        ');
  console.log('================================================================\n');

  // --------------------------------------------------------------------------
  // PILLAR 1: Zero-Bloat Gateway (Context & Cost Optimizer)
  // --------------------------------------------------------------------------
  console.log('--- Testing Pillar 1: Zero-Bloat Gateway ---');
  const router = new SemanticRouter();
  const virtualizer = new ContextVirtualizer(path.join(os.tmpdir(), 'br_test_virtual_ctx'));

  // Test 1.1: Token Reduction Calculation with single route_tool vs 50 tools catalog
  for (let i = 1; i <= 40; i++) {
    router.registerTool({
      name: `custom_tool_${i}`,
      server: 'mock-server',
      description: `Performs complex operations on resource type ${i} with extended parameters and schemas.`,
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Entity identifier' },
          metadata: { type: 'object', properties: { tag: { type: 'string' } } },
          filter: { type: 'array', items: { type: 'string' } },
          limit: { type: 'number', default: 50 }
        },
        required: ['id']
      }
    });
  }

  const allTools = router.listTools();
  const allToolsJson = JSON.stringify(allTools);
  const allToolsTokens = Math.ceil(allToolsJson.length / 4);

  const routeToolSchema = {
    name: 'route_tool',
    description: 'Semantic intent router with JIT schema retrieval.',
    inputSchema: {
      type: 'object',
      properties: { intent: { type: 'string' }, candidateServer: { type: 'string' } },
      required: ['intent']
    }
  };
  const routeToolTokens = Math.ceil(JSON.stringify(routeToolSchema).length / 4);
  const catalogTokenReduction = Number((((allToolsTokens - routeToolTokens) / allToolsTokens) * 100).toFixed(1));

  record({
    pillar: 'Pillar 1',
    testName: 'Catalog Token Reduction (JIT Route Tool)',
    claimedParameter: '~99% token reduction on initial schema injection',
    measuredResult: `Reduced from ${allToolsTokens} to ${routeToolTokens} tokens (${catalogTokenReduction}% reduction across ${allTools.length} tools)`,
    passed: catalogTokenReduction >= 90
  });

  // Test 1.2: JIT Semantic Routing Accuracy
  const routeMatch = await router.route({ intent: 'query postgresql database customer records' });
  const isPostgresMatch = routeMatch.matchedTool === 'postgres-query';
  record({
    pillar: 'Pillar 1',
    testName: 'Semantic Intent Routing & Schema Fetch',
    claimedParameter: 'Resolves natural language intent to exact schema JIT',
    measuredResult: `Matched tool: '${routeMatch.matchedTool}' (confidence: ${routeMatch.confidence}, server: ${routeMatch.serverName})`,
    passed: isPostgresMatch && routeMatch.confidence > 0.2
  });

  // Test 1.3: Virtualize 50KB Payload & Compression Handle
  const rows = [];
  for (let i = 0; i < 500; i++) {
    rows.push({
      id: i,
      uuid: `usr_981a_${i}_${Math.random().toString(36).substring(7)}`,
      email: `user_${i}@enterprise-corp.internal`,
      accountBalance: 15420.50 + i,
      role: i % 5 === 0 ? 'admin' : 'viewer',
      bio: 'Enterprise customer with multiple linked accounts and transaction histories'
    });
  }
  const largePayload = JSON.stringify(rows, null, 2);
  const largePayloadBytes = Buffer.byteLength(largePayload, 'utf-8');

  // Embed a secret AWS key in the payload to test DLP redaction
  const secretKey = 'AKIAIOSFODNN7EXAMPLE';
  const payloadWithSecret = `// Secret config\nconst aws_key = "${secretKey}";\n` + largePayload;

  const handle = virtualizer.virtualize({
    rawContent: payloadWithSecret,
    label: 'database_dump_50kb'
  });

  const reductionPct = handle.tokenReductionPercentage ?? 0;
  record({
    pillar: 'Pillar 1',
    testName: 'Context Virtualization Handle Generation',
    claimedParameter: 'Virtual reference (ctx_...) with >85% token reduction on 50KB payload',
    measuredResult: `Handle: ${handle.handleId}, Size: ${(largePayloadBytes / 1024).toFixed(1)} KB, Token reduction: ${reductionPct}% (Saved ${handle.tokensSaved} tokens)`,
    passed: handle.handleId.startsWith('ctx_') && reductionPct >= 85
  });

  // Test 1.4: DLP Redaction in Preview Snippet
  const hasSecretInPreview = handle.previewSnippet ? handle.previewSnippet.includes(secretKey) : false;
  const hasMaskInPreview = handle.previewSnippet ? handle.previewSnippet.includes('REDACTED_AWS_KEY') : false;
  record({
    pillar: 'Pillar 1',
    testName: 'Automated DLP Secret Redaction',
    claimedParameter: 'Automated sensitive data redaction in virtualized preview snippet',
    measuredResult: hasMaskInPreview && !hasSecretInPreview
      ? 'AWS Key successfully redacted with [REDACTED_AWS_KEY:MPLE] mask'
      : 'Secret was NOT redacted properly',
    passed: Boolean(hasMaskInPreview && !hasSecretInPreview)
  });

  // Test 1.5: Content Resolution
  const resolvedContent = virtualizer.resolve(handle.handleId);
  record({
    pillar: 'Pillar 1',
    testName: 'Virtual Content Resolution',
    claimedParameter: 'Full payload retrievable by virtual handle',
    measuredResult: resolvedContent ? `Retrieved ${Buffer.byteLength(resolvedContent, 'utf-8')} bytes intact` : 'Failed to resolve',
    passed: resolvedContent !== null && resolvedContent.length === payloadWithSecret.length
  });

  // --------------------------------------------------------------------------
  // PILLAR 2: Swarm Pre-Flight Safety Simulator
  // --------------------------------------------------------------------------
  console.log('\n--- Testing Pillar 2: Swarm Pre-Flight Safety Simulator ---');
  const swarmEngine = new SwarmNativeEngine();

  // Test 2.1: Latency Benchmark for 50 Personas
  const iterations = 10;
  const latencies: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await swarmEngine.simulate({
      targetDiffOrCommand: `
--- a/auth/login.ts
+++ b/auth/login.ts
@@ -10,2 +10,4 @@
+  const query = "SELECT * FROM users WHERE username = '" + req.body.username + "'";
+  db.execute(query);
`,
      agentCount: 50,
      intensity: 'FAST'
    });
    const t1 = performance.now();
    latencies.push(t1 - t0);
  }

  const minLat = Math.min(...latencies).toFixed(2);
  const maxLat = Math.max(...latencies).toFixed(2);
  const avgLat = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2);

  record({
    pillar: 'Pillar 2',
    testName: '50-Persona In-Memory Simulation Latency',
    claimedParameter: '50 simulated personas in memory in under 50ms',
    measuredResult: `Avg: ${avgLat}ms (Min: ${minLat}ms, Max: ${maxLat}ms across ${iterations} runs)`,
    passed: parseFloat(avgLat) <= 50,
    notes: 'Sub-millisecond in-memory native engine'
  });

  // Test 2.2: Persona 1 - Security Hacker (SQL Injection & Auth Bypass)
  const hacker = createHackerPersona('hacker-01');
  const hackerFindings = await hacker.evaluate(
    `const user = await db.query("SELECT * FROM accounts WHERE token = '" + req.headers.token + "'");`,
    { round: 1 }
  );
  const caughtSqlInnHacker = hackerFindings.some(f => f.attackVector === 'SQL_INJECTION' || f.attackVector === 'AUTH_BYPASS');
  record({
    pillar: 'Pillar 2',
    testName: 'Persona: Security Hacker (SQLi & Auth)',
    claimedParameter: 'Security Hacker catches SQL injection and auth bypasses',
    measuredResult: `Found ${hackerFindings.length} attack vectors: ${hackerFindings.map(f => f.attackVector).join(', ')}`,
    passed: caughtSqlInnHacker
  });

  // Test 2.3: Persona 2 - Confused User (Deep unhandled property & unprotected JSON.parse)
  const confused = createConfusedUserPersona('confused-01');
  const confusedDiff = `
function processUserInput(req) {
  const city = req.body.address.city;
  const config = JSON.parse(req.body.customConfig);
  return { city, config };
}
`;
  const confusedFindings = await confused.evaluate(confusedDiff, { round: 1 });
  record({
    pillar: 'Pillar 2',
    testName: 'Persona: Confused User (Invalid Inputs & Missing Optional Chaining)',
    claimedParameter: 'Confused User tests invalid inputs, missing fields, unhandled exceptions',
    measuredResult: `Found ${confusedFindings.length} attack vectors: ${confusedFindings.map(f => f.attackVector).join(', ')}`,
    passed: confusedFindings.length > 0
  });

  // Test 2.4: Persona 3 - Legacy System (Network latency & unhandled timeouts)
  const legacy = createLegacySystemPersona('legacy-01');
  const legacyFindings = await legacy.evaluate(
    `async function fetchExternal() { return await fetch('http://legacy-api:8080/data'); }`,
    { round: 1 }
  );
  record({
    pillar: 'Pillar 2',
    testName: 'Persona: Legacy System (Network Latency & Timeouts)',
    claimedParameter: 'Legacy System tests connection drops, stale cache, timeouts',
    measuredResult: `Found ${legacyFindings.length} findings: ${legacyFindings.map(f => f.attackVector).join(', ')}`,
    passed: legacyFindings.length > 0
  });

  // Test 2.5: Persona 4 - Concurrency Racer (Check-then-act race conditions)
  const racer = createConcurrencyRacerPersona('racer-01');
  const racerDiff = `
async function withdraw(userId, amount) {
  if (balance >= amount) {
    await deductBalance(userId, amount);
  }
}
`;
  const racerFindings = await racer.evaluate(racerDiff, { round: 1 });
  record({
    pillar: 'Pillar 2',
    testName: 'Persona: Concurrency Racer (Race Conditions & TOCTOU)',
    claimedParameter: 'Concurrency Racer tests simultaneous access and race conditions',
    measuredResult: `Found ${racerFindings.length} findings: ${racerFindings.map(f => f.attackVector).join(', ')}`,
    passed: racerFindings.length > 0
  });

  // Test 2.6: Persona 5 - Data Corruptor (Null byte poisoning & path injection)
  const corruptor = createDataCorruptorPersona('corruptor-01');
  const corruptorDiff = `
function getReport(req, res) {
  const filePath = path.join('/var/reports', req.query.filename);
  const data = fs.readFileSync(filePath, 'utf-8');
  res.send(data);
}
`;
  const corruptorFindings = await corruptor.evaluate(corruptorDiff, { round: 1 });
  record({
    pillar: 'Pillar 2',
    testName: 'Persona: Data Corruptor (Null Bytes & Type Confusion)',
    claimedParameter: 'Data Corruptor injects Unicode edge cases, null bytes, poison payloads',
    measuredResult: `Found ${corruptorFindings.length} findings: ${corruptorFindings.map(f => f.attackVector).join(', ')}`,
    passed: corruptorFindings.length > 0
  });

  // Test 2.7: Risk Heatmap & Blast Radius Evaluation
  const benignCmd = BlastRadiusEngine.evaluate('ls -la src/');
  const destructiveCmd = BlastRadiusEngine.evaluate('DROP DATABASE production;');

  const swarmSim = await swarmEngine.simulate({
    targetDiffOrCommand: `
const user = await db.query("SELECT * FROM users WHERE id = '" + req.body.id + "'");
if (balance >= amount) await deductBalance(amount);
`,
    agentCount: 50
  });
  const swarmHeatmap = generateHeatmap('injection_diff', swarmSim.criticalFindings, swarmSim.prRiskScore);

  record({
    pillar: 'Pillar 2',
    testName: 'Visual Risk Heatmap & Danger Scoring (0-100)',
    claimedParameter: 'Generates instant Risk Heatmap with accurate danger score (0-100)',
    measuredResult: `Benign cmd danger: ${benignCmd.dangerScore}/100, Destructive cmd danger: ${destructiveCmd.dangerScore}/100, Swarm code danger: ${swarmHeatmap.overallScore}/100 (${swarmSim.verdict})`,
    passed: benignCmd.dangerScore <= 15 && destructiveCmd.dangerScore >= 85 && swarmHeatmap.overallScore >= 70
  });

  // --------------------------------------------------------------------------
  // PILLAR 3: TDD Enforcer & AST Quality Gate
  // --------------------------------------------------------------------------
  console.log('\n--- Testing Pillar 3: TDD Enforcer & AST Quality Gate ---');
  const tdd = TddStateMachine.getInstance();
  const featureId = `feature-auth-${Date.now()}`;

  // Test 3.1: Initial State & Production Write Lock
  const initialState = tdd.getState(featureId);
  const writeBeforeTest = tdd.canModifyProductionCode(featureId, 'src/auth/service.ts');
  record({
    pillar: 'Pillar 3',
    testName: 'TDD State Machine: Production Write Lock in IDLE',
    claimedParameter: 'Agent cannot modify production files until it writes a test that fails',
    measuredResult: `Phase: ${initialState.phase}, canModifyProductionCode: allowed=${writeBeforeTest.allowed} ('${writeBeforeTest.reason}')`,
    passed: !writeBeforeTest.allowed && initialState.phase === TddPhase.IDLE
  });

  // Test 3.2: Allow Test File Modification
  const writeTestFile = tdd.canModifyProductionCode(featureId, 'tests/auth/service.test.ts');
  record({
    pillar: 'Pillar 3',
    testName: 'TDD State Machine: Test File Modification Allowed',
    claimedParameter: 'Allows editing test/spec files during test creation',
    measuredResult: `Allowed test file write: ${writeTestFile.allowed}`,
    passed: writeTestFile.allowed
  });

  // Test 3.3: Register Failing Test & Verify Failure (RED Phase)
  tdd.registerFailingTest(featureId, 'tests/auth/service.test.ts', 'expect(auth.login).toBeDefined()');
  const redResult = tdd.verifyTestFailure(featureId, 'FAIL tests/auth/service.test.ts\n● auth login should exist\n AssertionError: expected undefined to be defined');
  const writeAfterRed = tdd.canModifyProductionCode(featureId, 'src/auth/service.ts');

  record({
    pillar: 'Pillar 3',
    testName: 'TDD State Machine: RED Phase Confirmation',
    claimedParameter: 'Verifies failing test output, confirms RED, then permits production code change',
    measuredResult: `Verified: ${redResult.verified}, New Phase: ${redResult.state.phase}, Can modify prod code now: ${writeAfterRed.allowed}`,
    passed: redResult.verified && writeAfterRed.allowed
  });

  // Test 3.4: Verify Test Pass (GREEN Phase)
  const greenResult = tdd.verifyTestPass(featureId, 'PASS tests/auth/service.test.ts\n✓ auth login should exist (12ms)\nTest Suites: 1 passed, 1 total');
  record({
    pillar: 'Pillar 3',
    testName: 'TDD State Machine: GREEN -> REFACTOR Phase Transition',
    claimedParameter: 'Transitions to REFACTOR on verified passing test output',
    measuredResult: `Verified: ${greenResult.verified}, Phase: ${greenResult.state.phase}`,
    passed: greenResult.verified && greenResult.state.phase === TddPhase.REFACTOR
  });

  // Test 3.5: AST Code Critique - Swallowed Error in Empty Catch
  const emptyCatchCode = `
function loadConfig() {
  try {
    const raw = fs.readFileSync('config.json');
    return JSON.parse(raw);
  } catch (err) {
  }
}
`;
  const critiqueEmptyCatch = critiqueCode(emptyCatchCode, 'src/config.ts');
  const caughtEmptyCatch = critiqueEmptyCatch.findings.some(f => f.ruleId === 'EMPTY_CATCH_BLOCK' || f.category === 'ERROR_HANDLING');
  record({
    pillar: 'Pillar 3',
    testName: 'AST Critique: Empty Catch Block Detection',
    claimedParameter: 'Critique detects swallowed errors in empty try/catch blocks',
    measuredResult: `Score: ${critiqueEmptyCatch.score}/100, Detected: ${caughtEmptyCatch} (${critiqueEmptyCatch.findings.length} findings)`,
    passed: caughtEmptyCatch
  });

  // Test 3.6: AST Code Critique - Dangerous Shell Sinks
  const dangerousSinkCode = `
function runBuild(cmd) {
  const { exec } = require('child_process');
  exec(cmd);
}
`;
  const critiqueSink = critiqueCode(dangerousSinkCode, 'src/builder.ts');
  const caughtSink = critiqueSink.findings.some(f => f.ruleId === 'DANGEROUS_SHELL_SINK' || f.category === 'SECURITY');
  record({
    pillar: 'Pillar 3',
    testName: 'AST Critique: Dangerous Shell Sink Detection',
    claimedParameter: 'Critique detects dangerous execution sinks (exec/eval)',
    measuredResult: `Detected: ${caughtSink}, Severity: ${critiqueSink.findings[0]?.severity}`,
    passed: caughtSink
  });

  // --------------------------------------------------------------------------
  // PILLAR 4: Zero-Trust Compliance Ledger & Learning Flywheel
  // --------------------------------------------------------------------------
  console.log('\n--- Testing Pillar 4: Zero-Trust Compliance Ledger & Learning Flywheel ---');

  // Test 4.1: HMAC-SHA256 Step-Up Token Generation & Anti-Replay
  TokenManager.setSigningKey('enterprise-secret-key-0123456789abcdef');
  const approval = TokenManager.generateToken('database_drop', 'fp_schema_users_drop', 'security_officer_alice', 300);
  const parts = approval.token.split('.');
  const isHmacFormat = parts.length === 2 && approval.payload.tokenId.startsWith('br-tok-');

  // Verify first time
  const verify1 = TokenManager.verifyToken(approval.token, 'database_drop');
  TokenManager.consumeToken(approval.payload.tokenId);

  // Attempt replay (verify second time)
  const verifyReplay = TokenManager.verifyToken(approval.token, 'database_drop');

  record({
    pillar: 'Pillar 4',
    testName: 'Cryptographic Step-Up Token & Anti-Replay',
    claimedParameter: 'Single-use HMAC-SHA256 signed approval token that cannot be replayed',
    measuredResult: `Format valid: ${isHmacFormat}, First verification: valid=${verify1.valid}, Replay attempt: valid=${verifyReplay.valid} ('${verifyReplay.error}')`,
    passed: isHmacFormat && verify1.valid && !verifyReplay.valid
  });

  // Test 4.2: Token Tamper Rejection
  const tamperedToken = approval.token.slice(0, -3) + 'XYZ';
  const verifyTampered = TokenManager.verifyToken(tamperedToken, 'database_drop');
  record({
    pillar: 'Pillar 4',
    testName: 'Step-Up Token Tamper Resistance',
    claimedParameter: 'Cryptographically rejects altered token payload or signature',
    measuredResult: `Tampered token verification: valid=${verifyTampered.valid} ('${verifyTampered.error}')`,
    passed: !verifyTampered.valid
  });

  // Test 4.3: Tamper-Evident Audit Ledger Hash Chain & Tamper Detection
  const tempLedgerPath = path.join(os.tmpdir(), `audit_ledger_test_${Date.now()}.jsonl`);
  AuditLedger.initialize(tempLedgerPath);

  // Record 5 chained events
  for (let i = 1; i <= 5; i++) {
    AuditLedger.record({
      toolName: `tool_${i}`,
      callerId: 'agent_evaluator',
      category: ActionCategory.FILESYSTEM,
      decision: PolicyDecision.ALLOW,
      dangerScore: i * 10,
      severity: SeverityLevel.LOW,
      reasons: [`Action ${i}`],
      dlpFindingsCount: 0,
      rawPayload: { actionId: i }
    });
  }

  const intactCheck = AuditLedger.verifyIntegrity();

  // Tamper with record 3 in the JSONL file
  const lines = fs.readFileSync(tempLedgerPath, 'utf-8').trim().split('\n');
  const entry3 = JSON.parse(lines[2]);
  entry3.dangerScore = 99; // Tamper score
  lines[2] = JSON.stringify(entry3);
  fs.writeFileSync(tempLedgerPath, lines.join('\n') + '\n', 'utf-8');

  // Reload ledger from disk and verify chain detects tampering
  AuditLedger.initialize(tempLedgerPath);
  const tamperedCheck = AuditLedger.verifyIntegrity();

  // Cleanup temp ledger
  try { fs.unlinkSync(tempLedgerPath); } catch {}

  record({
    pillar: 'Pillar 4',
    testName: 'Tamper-Evident Hash-Chained Audit Ledger',
    claimedParameter: 'Cryptographically hash-chained log detects altered records or broken chain links',
    measuredResult: `Intact check: intact=${intactCheck.intact}, Post-tampering check: intact=${tamperedCheck.intact} (tamperedIndex: ${tamperedCheck.tamperedIndex}, error: '${tamperedCheck.error}')`,
    passed: intactCheck.intact && !tamperedCheck.intact
  });

  // Test 4.4: Learning Flywheel Local SQLite Indexing
  const tempDbPath = path.join(os.tmpdir(), `flywheel_test_${Date.now()}.db`);
  const flywheel = new DataFlywheel(tempDbPath);

  const mockSimResult = {
    simulationId: 'sim_eval_01',
    prRiskScore: 85,
    verdict: 'BLOCK' as const,
    personasSimulated: 50,
    criticalFindings: [
      {
        personaType: 'HACKER',
        attackVector: 'SQL_INJECTION',
        description: 'Direct string concatenation in query',
        severity: 'CRITICAL' as const,
        suggestedTest: 'it("parameterizes query")',
        reproductionSteps: ['inject payload']
      }
    ],
    divergenceFromStatic: 45,
    durationMs: 38.5,
    heatmapAscii: '=== HEATMAP ===',
    timestamp: new Date().toISOString()
  };

  flywheel.recordSimulation(mockSimResult, {
    targetDiffOrCommand: 'const query = "SELECT * FROM secrets WHERE id = " + id;',
    contextDescription: 'Evaluator injection test',
    agentCount: 50
  });

  const stats = flywheel.getStats();
  const hasSqlInjectionVector = stats.topAttackVectors.some(v => v.vector === 'SQL_INJECTION');

  // Cleanup temp db
  try {
    fs.unlinkSync(tempDbPath);
    if (fs.existsSync(tempDbPath + '-wal')) fs.unlinkSync(tempDbPath + '-wal');
    if (fs.existsSync(tempDbPath + '-shm')) fs.unlinkSync(tempDbPath + '-shm');
  } catch {}

  record({
    pillar: 'Pillar 4',
    testName: 'Learning Flywheel SQLite Indexing',
    claimedParameter: 'Indexes attack patterns locally in SQLite to learn and adapt without cloud calls',
    measuredResult: `Total simulations: ${stats.totalSimulations}, Attack vectors learned: ${stats.attackVectorsLearned}, Top vector: ${stats.topAttackVectors[0]?.vector}`,
    passed: stats.totalSimulations === 1 && hasSqlInjectionVector
  });

  console.log('\n================================================================');
  console.log('                    EVALUATION SUMMARY                          ');
  console.log('================================================================');
  const totalTests = results.length;
  const passedTests = results.filter(r => r.passed).length;
  console.log(`Total Verification Tests: ${totalTests}`);
  console.log(`Passed: ${passedTests}`);
  console.log(`Failed: ${totalTests - passedTests}`);
  console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%\n`);
}

runEvaluation().catch(err => {
  console.error('Fatal evaluation error:', err);
  process.exit(1);
});
