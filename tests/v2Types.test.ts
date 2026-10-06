import test from 'node:test';
import assert from 'node:assert';
import {
  RouteToolSchema,
  VirtualizeContextSchema,
  SimulateSwarmImpactSchema,
  AdversarialPersonaReviewSchema,
  BlastRadiusHeatmapSchema,
  EnforceTddStateSchema,
  GenerateSocraticSpecSchema,
  SpawnWorktreeSubagentSchema,
  AutomatedCodeCritiqueSchema,
  GetSecurityPostureSchema
} from '../src/types.js';
import {
  RouteToolParams,
  RouteToolResult,
  VirtualizeContextParams,
  VirtualContextHandle,
  RegisteredToolSchema
} from '../src/gateway/types.js';
import {
  SwarmSimulationRequest,
  SwarmSimulationResult,
  AdversarialPersona,
  PersonaFinding,
  HeatmapMatrix
} from '../src/swarm/types.js';
import {
  TddPhase,
  TddStateContext,
  SocraticSpecResult,
  WorktreeResult,
  CodeCritiqueFinding,
  CodeCritiqueResult
} from '../src/quality/types.js';

test('Zod Schemas - RouteToolSchema validates inputs and applies defaults', () => {
  const minimal = RouteToolSchema.parse({ intent: 'query users' });
  assert.strictEqual(minimal.intent, 'query users');
  assert.strictEqual(minimal.executeImmediately, false);
  assert.strictEqual(minimal.candidateServer, undefined);
  assert.strictEqual(minimal.toolArguments, undefined);

  const full = RouteToolSchema.parse({
    intent: 'deploy to staging',
    candidateServer: 'deployer',
    executeImmediately: true,
    toolArguments: { targetEnv: 'staging', force: true }
  });
  assert.strictEqual(full.executeImmediately, true);
  assert.strictEqual(full.candidateServer, 'deployer');
  assert.deepStrictEqual(full.toolArguments, { targetEnv: 'staging', force: true });

  assert.throws(() => RouteToolSchema.parse({}), /intent/);
});

test('Zod Schemas - VirtualizeContextSchema validates inputs and applies defaults', () => {
  const minimal = VirtualizeContextSchema.parse({ rawContent: 'sample payload data' });
  assert.strictEqual(minimal.rawContent, 'sample payload data');
  assert.strictEqual(minimal.label, 'payload');
  assert.strictEqual(minimal.retentionTtlSeconds, 3600);

  const custom = VirtualizeContextSchema.parse({
    rawContent: 'custom log data',
    label: 'server-logs',
    retentionTtlSeconds: 1800
  });
  assert.strictEqual(custom.label, 'server-logs');
  assert.strictEqual(custom.retentionTtlSeconds, 1800);

  assert.throws(() => VirtualizeContextSchema.parse({}), /rawContent/);
});

test('Zod Schemas - SimulateSwarmImpactSchema validates inputs, bounds, and defaults', () => {
  const minimal = SimulateSwarmImpactSchema.parse({ targetDiffOrCommand: 'rm -rf /tmp' });
  assert.strictEqual(minimal.targetDiffOrCommand, 'rm -rf /tmp');
  assert.strictEqual(minimal.contextDescription, '');
  assert.strictEqual(minimal.agentCount, 25);
  assert.strictEqual(minimal.intensity, 'FAST');
  assert.strictEqual(minimal.focusAreas, undefined);

  const full = SimulateSwarmImpactSchema.parse({
    targetDiffOrCommand: 'git diff HEAD~1',
    contextDescription: 'Auth middleware refactor',
    agentCount: 50,
    intensity: 'DEEP',
    focusAreas: ['SECURITY', 'CONCURRENCY']
  });
  assert.strictEqual(full.agentCount, 50);
  assert.strictEqual(full.intensity, 'DEEP');
  assert.deepStrictEqual(full.focusAreas, ['SECURITY', 'CONCURRENCY']);

  // agentCount bounds [5, 50]
  assert.throws(() => SimulateSwarmImpactSchema.parse({ targetDiffOrCommand: 'x', agentCount: 4 }));
  assert.throws(() => SimulateSwarmImpactSchema.parse({ targetDiffOrCommand: 'x', agentCount: 51 }));

  // invalid intensity enum
  assert.throws(() => SimulateSwarmImpactSchema.parse({ targetDiffOrCommand: 'x', intensity: 'EXTREME' }));

  // invalid focusArea enum
  assert.throws(() => SimulateSwarmImpactSchema.parse({ targetDiffOrCommand: 'x', focusAreas: ['INVALID'] }));
});

test('Zod Schemas - AdversarialPersonaReviewSchema validates personas, depth, and defaults', () => {
  const minimal = AdversarialPersonaReviewSchema.parse({ targetDiffOrCommand: 'code diff' });
  assert.strictEqual(minimal.personaType, 'ALL');
  assert.strictEqual(minimal.depth, 3);

  const personas = ['HACKER', 'CONFUSED_USER', 'LEGACY_SYSTEM', 'CONCURRENCY_RACER', 'ALL'] as const;
  for (const persona of personas) {
    const res = AdversarialPersonaReviewSchema.parse({ targetDiffOrCommand: 'diff', personaType: persona, depth: 5 });
    assert.strictEqual(res.personaType, persona);
  }

  // depth bounds [1, 10]
  assert.throws(() => AdversarialPersonaReviewSchema.parse({ targetDiffOrCommand: 'diff', depth: 0 }));
  assert.throws(() => AdversarialPersonaReviewSchema.parse({ targetDiffOrCommand: 'diff', depth: 11 }));

  // invalid personaType
  assert.throws(() => AdversarialPersonaReviewSchema.parse({ targetDiffOrCommand: 'diff', personaType: 'UNKNOWN' }));
});

test('Zod Schemas - BlastRadiusHeatmapSchema validates formats and defaults', () => {
  const minimal = BlastRadiusHeatmapSchema.parse({ targetDiffOrCommand: 'command' });
  assert.strictEqual(minimal.format, 'MARKDOWN');
  assert.strictEqual(minimal.context, undefined);

  const ascii = BlastRadiusHeatmapSchema.parse({ targetDiffOrCommand: 'cmd', format: 'ASCII', context: { env: 'prod' } });
  assert.strictEqual(ascii.format, 'ASCII');
  assert.strictEqual(ascii.context?.env, 'prod');

  const json = BlastRadiusHeatmapSchema.parse({ targetDiffOrCommand: 'cmd', format: 'JSON' });
  assert.strictEqual(json.format, 'JSON');

  assert.throws(() => BlastRadiusHeatmapSchema.parse({ targetDiffOrCommand: 'cmd', format: 'HTML' }));
});

test('Zod Schemas - EnforceTddStateSchema validates TDD actions and fields', () => {
  const actions = ['GET_STATE', 'REGISTER_FAILING_TEST', 'VERIFY_TEST_FAILURE', 'VERIFY_TEST_PASS', 'RESET'] as const;
  for (const action of actions) {
    const res = EnforceTddStateSchema.parse({
      featureName: 'auth-token',
      action,
      testFilePath: 'tests/auth.test.ts',
      testOutput: 'AssertionError: expected true'
    });
    assert.strictEqual(res.featureName, 'auth-token');
    assert.strictEqual(res.action, action);
  }

  assert.throws(() => EnforceTddStateSchema.parse({ featureName: 'auth', action: 'INVALID_ACTION' }));
  assert.throws(() => EnforceTddStateSchema.parse({ action: 'GET_STATE' }));
});

test('Zod Schemas - GenerateSocraticSpecSchema validates spec generation params and defaults', () => {
  const minimal = GenerateSocraticSpecSchema.parse({ featureRequirement: 'Add rate limiting to API' });
  assert.strictEqual(minimal.featureRequirement, 'Add rate limiting to API');
  assert.strictEqual(minimal.depth, 'DETAILED');
  assert.strictEqual(minimal.targetComponents, undefined);

  const full = GenerateSocraticSpecSchema.parse({
    featureRequirement: 'Add rate limiting to API',
    depth: 'EXHAUSTIVE',
    targetComponents: ['gateway', 'redis']
  });
  assert.strictEqual(full.depth, 'EXHAUSTIVE');
  assert.deepStrictEqual(full.targetComponents, ['gateway', 'redis']);

  const highLevel = GenerateSocraticSpecSchema.parse({
    featureRequirement: 'Add rate limiting',
    depth: 'HIGH_LEVEL'
  });
  assert.strictEqual(highLevel.depth, 'HIGH_LEVEL');

  assert.throws(() => GenerateSocraticSpecSchema.parse({ depth: 'DETAILED' }));
  assert.throws(() => GenerateSocraticSpecSchema.parse({ featureRequirement: 'req', depth: 'INVALID' }));
});

test('Zod Schemas - SpawnWorktreeSubagentSchema validates agent worktree params and defaults', () => {
  const minimal = SpawnWorktreeSubagentSchema.parse({ agentId: 'agent-42', branchName: 'feat/isolate' });
  assert.strictEqual(minimal.agentId, 'agent-42');
  assert.strictEqual(minimal.branchName, 'feat/isolate');
  assert.strictEqual(minimal.baseBranch, 'main');

  const custom = SpawnWorktreeSubagentSchema.parse({
    agentId: 'agent-43',
    branchName: 'feat/develop',
    baseBranch: 'develop'
  });
  assert.strictEqual(custom.baseBranch, 'develop');

  assert.throws(() => SpawnWorktreeSubagentSchema.parse({ agentId: 'agent-42' }));
  assert.throws(() => SpawnWorktreeSubagentSchema.parse({ branchName: 'feat/test' }));
});

test('Zod Schemas - AutomatedCodeCritiqueSchema validates critique params and defaults', () => {
  const minimal = AutomatedCodeCritiqueSchema.parse({ diffOrCode: 'const x = eval(payload);' });
  assert.strictEqual(minimal.diffOrCode, 'const x = eval(payload);');
  assert.strictEqual(minimal.strictSecurity, true);
  assert.strictEqual(minimal.filePath, undefined);

  const custom = AutomatedCodeCritiqueSchema.parse({
    diffOrCode: 'const x = 1;',
    filePath: 'src/config.ts',
    strictSecurity: false
  });
  assert.strictEqual(custom.filePath, 'src/config.ts');
  assert.strictEqual(custom.strictSecurity, false);

  assert.throws(() => AutomatedCodeCritiqueSchema.parse({}));
});

test('Zod Schemas - GetSecurityPostureSchema validates posture params and defaults', () => {
  const empty = GetSecurityPostureSchema.parse({});
  assert.strictEqual(empty.includeHistory, false);

  const withHist = GetSecurityPostureSchema.parse({ includeHistory: true });
  assert.strictEqual(withHist.includeHistory, true);
});

test('Gateway Types - interfaces correctly describe objects', () => {
  const toolParams: RouteToolParams = {
    intent: 'search documents',
    candidateServer: 'search-mcp',
    executeImmediately: false,
    toolArguments: { query: 'blast radius' }
  };
  assert.strictEqual(toolParams.intent, 'search documents');

  const registeredSchema: RegisteredToolSchema = {
    name: 'search_docs',
    description: 'Searches documentation files',
    serverName: 'search-mcp',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
    keywords: ['search', 'docs'],
    category: 'INFORMATION'
  };
  assert.strictEqual(registeredSchema.name, 'search_docs');

  const toolResult: RouteToolResult = {
    matchedTool: 'search_docs',
    confidence: 0.95,
    serverName: 'search-mcp',
    schema: registeredSchema,
    executed: false,
    reasoning: 'Intent matches search keyword with 95% confidence',
    tokensSaved: 1450,
    suggestedCall: { tool: 'search_docs', arguments: { query: 'blast radius' } }
  };
  assert.strictEqual(toolResult.confidence, 0.95);

  const virtParams: VirtualizeContextParams = {
    rawContent: 'abc',
    label: 'test',
    retentionTtlSeconds: 120
  };
  assert.strictEqual(virtParams.rawContent, 'abc');

  const virtHandle: VirtualContextHandle = {
    handleId: 'handle-123',
    label: 'test',
    originalBytes: 1024,
    preview: 'preview text...',
    tokensEstimated: 256,
    tokensSaved: 200,
    retentionTtlSeconds: 120,
    createdAt: '2026-10-06T00:00:00Z',
    expiresAt: '2026-10-06T00:02:00Z'
  };
  assert.strictEqual(virtHandle.handleId, 'handle-123');
});

test('Swarm Types - interfaces correctly describe simulation structures', () => {
  const finding: PersonaFinding = {
    personaType: 'HACKER',
    attackVector: 'IDOR',
    description: 'Direct object reference allows user data exfiltration',
    suggestedTest: 'testIdorAccessRestriction()',
    severity: 'HIGH',
    reproductionSteps: ['Send request with userId=1'],
    affectedEntity: 'UserEntity'
  };
  assert.strictEqual(finding.severity, 'HIGH');

  const req: SwarmSimulationRequest = {
    targetDiffOrCommand: 'patch auth',
    contextDescription: 'Auth middleware change',
    agentCount: 20,
    intensity: 'FAST',
    focusAreas: ['SECURITY']
  };
  assert.strictEqual(req.agentCount, 20);

  const res: SwarmSimulationResult = {
    simulationId: 'sim-abc-123',
    prRiskScore: 45,
    verdict: 'WARN',
    personasSimulated: 20,
    criticalFindings: [finding],
    heatmapAscii: '[ASCII Heatmap]',
    divergenceFromStatic: 15,
    durationMs: 2300,
    timestamp: '2026-10-06T00:00:00Z'
  };
  assert.strictEqual(res.prRiskScore, 45);

  const persona: AdversarialPersona = {
    id: 'hacker-01',
    name: 'Security Hacker',
    type: 'HACKER',
    description: 'Attacks auth and explores vulnerabilities',
    focusArea: 'SECURITY',
    evaluate: () => [finding]
  };
  assert.strictEqual(persona.id, 'hacker-01');

  const matrix: HeatmapMatrix = {
    dimensions: {
      components: ['Auth', 'Database'],
      riskLevels: ['SAFE', 'HIGH']
    },
    cells: [{
      component: 'Auth',
      risk: 'HIGH',
      score: 75,
      description: 'Critical authentication boundary affected'
    }],
    asciiTable: '| Auth | HIGH |',
    markdownTable: '| Component | Risk |\n| Auth | HIGH |',
    overallScore: 75
  };
  assert.strictEqual(matrix.overallScore, 75);
});

test('Quality Types - TddPhase enum and interfaces describe quality models', () => {
  assert.strictEqual(TddPhase.IDLE, 'IDLE');
  assert.strictEqual(TddPhase.RED_PENDING, 'RED_PENDING');
  assert.strictEqual(TddPhase.RED_CONFIRMED, 'RED_CONFIRMED');
  assert.strictEqual(TddPhase.GREEN_PENDING, 'GREEN_PENDING');
  assert.strictEqual(TddPhase.REFACTOR, 'REFACTOR');

  const context: TddStateContext = {
    activeFeature: 'oauth2-login',
    phase: TddPhase.RED_CONFIRMED,
    failingTestPath: 'tests/oauth.test.ts',
    failingTestAssertion: 'Expected 200 got 401',
    allowedWritePaths: ['tests/oauth.test.ts', 'src/auth/oauth.ts']
  };
  assert.strictEqual(context.phase, TddPhase.RED_CONFIRMED);

  const spec: SocraticSpecResult = {
    featureName: 'oauth2-login',
    summary: 'OAuth2 login flow specification',
    invariants: ['Token cannot be empty'],
    preconditions: ['User initiates login'],
    postconditions: ['Valid JWT returned'],
    edgeCases: [{
      scenario: 'Expired refresh token',
      input: 'expired_token_payload',
      expectedOutcome: 'HTTP 401 Unauthorized'
    }],
    securityRequirements: ['PKCE must be enforced'],
    testPlan: [{
      testName: 'should reject expired token',
      description: 'Tests expired token handling',
      assertionHint: 'assert.strictEqual(res.status, 401)'
    }],
    markdownSpec: '# Socratic Spec: OAuth2 Login'
  };
  assert.strictEqual(spec.featureName, 'oauth2-login');

  const worktree: WorktreeResult = {
    agentId: 'agent-sub-1',
    branchName: 'agent-sub-1-branch',
    worktreePath: '.blastradius/worktrees/agent-sub-1',
    baseBranch: 'main',
    status: 'ACTIVE',
    createdAt: '2026-10-06T00:00:00Z'
  };
  assert.strictEqual(worktree.status, 'ACTIVE');

  const finding: CodeCritiqueFinding = {
    ruleId: 'NO_EMPTY_CATCH',
    category: 'ERROR_HANDLING',
    severity: 'MEDIUM',
    filePath: 'src/service.ts',
    lineNumber: 42,
    lineContent: 'catch (e) {}',
    message: 'Empty catch block silently swallows error',
    suggestion: 'Log error or propagate exception'
  };
  assert.strictEqual(finding.ruleId, 'NO_EMPTY_CATCH');

  const critique: CodeCritiqueResult = {
    score: 85,
    passed: true,
    findingsCount: 1,
    findings: [finding],
    summary: 'Code quality passes with 1 warning',
    analyzedFiles: ['src/service.ts']
  };
  assert.strictEqual(critique.score, 85);
});
