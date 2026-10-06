import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { BlastRadiusEngine } from './analyzer/blastRadiusEngine.js';
import { DLPScanner } from './analyzer/dlpScanner.js';
import { PolicyEngine } from './policy/policyEngine.js';
import { TokenManager } from './security/tokenManager.js';
import { AuditLedger } from './security/auditLedger.js';
import { getEdition } from './security/edition.js';
import { SequenceDetector } from './analyzer/sequenceDetector.js';
import { calculateSecurityPosture } from './security/postureCalculator.js';
import { dataFlywheel } from './storage/flywheel.js';
import { semanticRouter } from './gateway/semanticRouter.js';
import { contextVirtualizer } from './gateway/contextVirtualizer.js';
import { SwarmNativeEngine } from './swarm/nativeEngine.js';
import {
  generateHeatmap,
  renderHeatmapAscii,
  renderHeatmapMarkdown
} from './swarm/heatmapGenerator.js';
import {
  createHackerPersona,
  createConfusedUserPersona,
  createLegacySystemPersona,
  createConcurrencyRacerPersona,
  createDataCorruptorPersona
} from './swarm/personas/index.js';
import { PersonaFinding, AdversarialPersona } from './swarm/types.js';
import { tddStateMachine } from './quality/tddStateMachine.js';
import { generateSocraticSpec } from './quality/socraticSpec.js';
import { worktreeManager } from './quality/worktreeManager.js';
import { critiqueCode } from './quality/codeCritique.js';
import {
  ActionCategory,
  PolicyDecision,
  SecurityPolicyConfig,
  SeverityLevel,
  AuditEntry,
  RouteToolSchema,
  VirtualizeContextSchema,
  SimulateSwarmImpactSchema,
  AdversarialPersonaReviewSchema,
  BlastRadiusHeatmapSchema,
  EnforceTddStateSchema,
  GenerateSocraticSpecSchema,
  SpawnWorktreeSubagentSchema,
  AutomatedCodeCritiqueSchema,
  VerifyAuditLogSchema,
  RequestConfirmationTokenSchema,
  GetSecurityPostureSchema
} from './types.js';

/** Ordinal severity ordering, so a signal can be compared against a decision. */
function severityWeight(severity: SeverityLevel): number {
  return [
    SeverityLevel.SAFE,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL
  ].indexOf(severity);
}

export class BlastRadiusServer {
  private server: Server;
  private policyEngine: PolicyEngine;
  /** Retained so sequence detection honours the same thresholds as the policy. */
  private policyConfig?: SecurityPolicyConfig;
  private swarmNativeEngine: SwarmNativeEngine;
  private totalInvocations = 0;
  private blockedCount = 0;
  private dlpRedactionsCount = 0;
  private criticalAvertedCount = 0;

  constructor(customPolicy?: SecurityPolicyConfig) {
    this.policyConfig = customPolicy;
    this.policyEngine = new PolicyEngine(customPolicy);
    this.swarmNativeEngine = new SwarmNativeEngine();
    AuditLedger.initialize();

    this.server = new Server(
      {
        name: 'blastradius-mcp',
        version: '2.0.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
  }

  /**
   * Dual-writes an audit event into both the HMAC-SHA256 append-only ledger
   * and the persistent SQLite DataFlywheel for compliance telemetry.
   */
  public dualWriteAuditEvent(params: {
    toolName: string;
    callerId: string;
    category?: ActionCategory;
    decision?: PolicyDecision;
    dangerScore?: number;
    severity?: SeverityLevel;
    reasons?: string[];
    dlpFindingsCount?: number;
    rawPayload?: any;
  }): AuditEntry {
    const entry = AuditLedger.record({
      toolName: params.toolName,
      callerId: params.callerId,
      category: params.category ?? ActionCategory.GENERIC,
      decision: params.decision ?? PolicyDecision.ALLOW,
      dangerScore: params.dangerScore ?? 0,
      severity: params.severity ?? SeverityLevel.SAFE,
      reasons: params.reasons ?? [],
      dlpFindingsCount: params.dlpFindingsCount ?? 0,
      rawPayload: params.rawPayload
    });

    try {
      dataFlywheel.recordAuditEvent({
        toolName: params.toolName,
        callerId: params.callerId,
        decision: params.decision ?? PolicyDecision.ALLOW,
        riskScore: params.dangerScore ?? 0,
        hash: entry.currentHash
      });
    } catch {
      // Non-blocking telemetry dual-write
    }

    return entry;
  }

  private async runPersonaReview(
    targetDiffOrCommand: string,
    personaType: 'HACKER' | 'CONFUSED_USER' | 'LEGACY_SYSTEM' | 'CONCURRENCY_RACER' | 'DATA_CORRUPTOR' | 'ALL',
    depth: number
  ): Promise<PersonaFinding[]> {
    const personas: AdversarialPersona[] = [];

    if (personaType === 'HACKER' || personaType === 'ALL') {
      personas.push(createHackerPersona('hacker-review-01'));
    }
    if (personaType === 'CONFUSED_USER' || personaType === 'ALL') {
      personas.push(createConfusedUserPersona('confused-review-01'));
    }
    if (personaType === 'LEGACY_SYSTEM' || personaType === 'ALL') {
      personas.push(createLegacySystemPersona('legacy-review-01'));
    }
    if (personaType === 'CONCURRENCY_RACER' || personaType === 'ALL') {
      personas.push(createConcurrencyRacerPersona('racer-review-01'));
    }
    if (personaType === 'DATA_CORRUPTOR' || personaType === 'ALL') {
      personas.push(createDataCorruptorPersona('corruptor-review-01'));
    }

    const allFindings: PersonaFinding[] = [];
    const rounds = Math.max(1, Math.min(10, depth));

    for (let round = 1; round <= rounds; round++) {
      const roundResults = await Promise.all(
        personas.map((p) =>
          p.evaluate(targetDiffOrCommand, {
            round,
            contextDescription: `Adversarial persona review round ${round} of ${rounds}`
          })
        )
      );
      allFindings.push(...roundResults.flat());
    }

    // Deduplicate by personaType + attackVector + description
    const seen = new Set<string>();
    const uniqueFindings: PersonaFinding[] = [];
    for (const finding of allFindings) {
      const key = `${finding.personaType}:${finding.attackVector}:${finding.description}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueFindings.push(finding);
      }
    }

    return uniqueFindings;
  }

  private setupHandlers(): void {
    // 1. List Available Tools - All 12 BlastRadius-Zero v2.0 Tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'route_tool',
            description:
              'Semantic and keyword intent router. Resolves natural-language intent to optimal downstream MCP tools with JIT schema retrieval and >85% token reduction.',
            inputSchema: {
              type: 'object',
              properties: {
                intent: {
                  type: 'string',
                  description: 'Intent or target tool to invoke.'
                },
                candidateServer: {
                  type: 'string',
                  description: 'Optional server or namespace hint.'
                },
                executeImmediately: {
                  type: 'boolean',
                  default: false,
                  description: 'Whether to execute if policy allows.'
                },
                toolArguments: {
                  type: 'object',
                  description: 'Arguments to pass to target tool.'
                }
              },
              required: ['intent']
            }
          },
          {
            name: 'virtualize_context',
            description:
              'Compresses large tool outputs, diffs, and logs into lightweight virtual handles, saving up to 90% agent context tokens.',
            inputSchema: {
              type: 'object',
              properties: {
                rawContent: {
                  type: 'string',
                  description: 'Raw text, logs, or payload to virtualize.'
                },
                label: {
                  type: 'string',
                  default: 'payload',
                  description: 'Label for reference.'
                },
                retentionTtlSeconds: {
                  type: 'number',
                  default: 3600,
                  description: 'TTL in seconds.'
                }
              },
              required: ['rawContent']
            }
          },
          {
            name: 'simulate_swarm_impact',
            description:
              'Fast in-memory pre-flight safety simulator. Spawns 25-50 adversarial virtual personas (Hacker, Confused User, Concurrency Racer, Data Corruptor) to stress-test diffs and commands in under 3 seconds.',
            inputSchema: {
              type: 'object',
              properties: {
                targetDiffOrCommand: {
                  type: 'string',
                  description: 'Code diff, command, or action to simulate.'
                },
                contextDescription: {
                  type: 'string',
                  default: '',
                  description: 'Context description of the change.'
                },
                agentCount: {
                  type: 'number',
                  default: 25,
                  description: 'Number of adversarial agents (5-50).'
                },
                intensity: {
                  type: 'string',
                  enum: ['FAST', 'DEEP'],
                  default: 'FAST',
                  description: 'Simulation intensity.'
                },
                focusAreas: {
                  type: 'array',
                  items: {
                    type: 'string',
                    enum: ['SECURITY', 'CONCURRENCY', 'USABILITY', 'DATA_INTEGRITY']
                  },
                  description: 'Focus areas for simulation.'
                }
              },
              required: ['targetDiffOrCommand']
            }
          },
          {
            name: 'adversarial_persona_review',
            description:
              'Deep targeted adversarial review executing specialized persona stress-testing (Hacker, Confused User, Legacy System, Concurrency Racer, Data Corruptor) with step-by-step reproduction steps.',
            inputSchema: {
              type: 'object',
              properties: {
                targetDiffOrCommand: {
                  type: 'string',
                  description: 'Code diff or action to review.'
                },
                personaType: {
                  type: 'string',
                  enum: ['HACKER', 'CONFUSED_USER', 'LEGACY_SYSTEM', 'CONCURRENCY_RACER', 'DATA_CORRUPTOR', 'ALL'],
                  default: 'ALL',
                  description: 'Adversarial persona type.'
                },
                depth: {
                  type: 'number',
                  default: 3,
                  description: 'Review depth rounds (1-10).'
                }
              },
              required: ['targetDiffOrCommand']
            }
          },
          {
            name: 'blast_radius_heatmap',
            description:
              'Visual Blast Radius Heatmap generator. Renders Markdown, ASCII, or JSON matrices evaluating impacted components, user classes, data sensitivity, and containment feasibility.',
            inputSchema: {
              type: 'object',
              properties: {
                targetDiffOrCommand: {
                  type: 'string',
                  description: 'Code diff or command to generate blast radius heatmap for.'
                },
                context: {
                  type: 'object',
                  description: 'Execution context.'
                },
                format: {
                  type: 'string',
                  enum: ['ASCII', 'MARKDOWN', 'JSON'],
                  default: 'MARKDOWN',
                  description: 'Output presentation format.'
                }
              },
              required: ['targetDiffOrCommand']
            }
          },
          {
            name: 'enforce_tdd_state',
            description:
              'Strict Test-Driven Development (TDD) quality gate state machine. Enforces Red -> Green -> Refactor cycle before permitting production code modifications.',
            inputSchema: {
              type: 'object',
              properties: {
                featureName: {
                  type: 'string',
                  description: 'Feature identifier being developed.'
                },
                action: {
                  type: 'string',
                  enum: [
                    'GET_STATE',
                    'REGISTER_FAILING_TEST',
                    'VERIFY_TEST_FAILURE',
                    'VERIFY_TEST_PASS',
                    'RESET',
                    'CHECK_PERMISSION'
                  ],
                  description: 'TDD state action.'
                },
                testFilePath: {
                  type: 'string',
                  description: 'Path to the test file.'
                },
                targetFilePath: {
                  type: 'string',
                  description: 'Path to target production code file when checking write permissions.'
                },
                testOutput: {
                  type: 'string',
                  description: 'Output of test execution.'
                }
              },
              required: ['featureName', 'action']
            }
          },
          {
            name: 'generate_socratic_spec',
            description:
              'Socratic requirement specification generator. Decomposes informal engineering requirements into rigorous, testable contracts with invariants, edge cases, and RED test plans.',
            inputSchema: {
              type: 'object',
              properties: {
                featureRequirement: {
                  type: 'string',
                  description: 'Feature requirement or user story.'
                },
                targetComponents: {
                  type: 'array',
                  items: {
                    type: 'string'
                  },
                  description: 'List of affected components.'
                },
                depth: {
                  type: 'string',
                  enum: ['HIGH_LEVEL', 'DETAILED', 'EXHAUSTIVE'],
                  default: 'DETAILED',
                  description: 'Spec detail depth.'
                }
              },
              required: ['featureRequirement']
            }
          },
          {
            name: 'spawn_worktree_subagent',
            description:
              'Isolates subagents in parallel Git worktrees (.blastradius/worktrees/<agentId>) to prevent workspace contamination and race conditions.',
            inputSchema: {
              type: 'object',
              properties: {
                agentId: {
                  type: 'string',
                  description: 'Unique agent identifier.'
                },
                branchName: {
                  type: 'string',
                  description: 'Branch name for worktree.'
                },
                baseBranch: {
                  type: 'string',
                  default: 'main',
                  description: 'Base branch to branch off of.'
                }
              },
              required: ['agentId', 'branchName']
            }
          },
          {
            name: 'automated_code_critique',
            description:
              'Senior-developer static and AST code critique. Detects silent error swallowing, dangerous sinks, missing test assertions, unchecked inputs, and unbounded queries.',
            inputSchema: {
              type: 'object',
              properties: {
                diffOrCode: {
                  type: 'string',
                  description: 'Code diff or content to critique.'
                },
                filePath: {
                  type: 'string',
                  description: 'Optional file path hint.'
                },
                strictSecurity: {
                  type: 'boolean',
                  default: true,
                  description: 'Enable strict security heuristic checks.'
                }
              },
              required: ['diffOrCode']
            }
          },
          {
            name: 'verify_audit_log',
            description:
              'Cryptographically verifies the immutable hash-chained audit ledger to detect tampering, deleted records, or unauthorized log modifications.',
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  default: 100,
                  description: 'Number of recent audit records to verify.'
                }
              }
            }
          },
          {
            name: 'request_confirmation_token',
            description:
              'Generates a time-bound, cryptographically signed (HMAC-SHA256) step-up approval token allowing an agent to execute high-impact actions when human consent is granted.',
            inputSchema: {
              type: 'object',
              properties: {
                toolName: {
                  type: 'string',
                  description: 'The specific tool name to authorize.'
                },
                actionFingerprint: {
                  type: 'string',
                  description: 'Unique signature or hash of the approved payload.'
                },
                requestedBy: {
                  type: 'string',
                  description: 'Identifier of the human supervisor or authorizing entity.'
                },
                ttlSeconds: {
                  type: 'number',
                  default: 300,
                  description: 'Token validity period in seconds (default: 300s).'
                },
                reason: {
                  type: 'string',
                  description: 'Justification for elevation.'
                }
              },
              required: ['toolName', 'actionFingerprint', 'requestedBy']
            }
          },
          {
            name: 'get_security_posture',
            description:
              'Returns real-time security posture score (0-100), active policy status, compliance metrics, TDD state summary, and data flywheel learning telemetry.',
            inputSchema: {
              type: 'object',
              properties: {
                includeHistory: {
                  type: 'boolean',
                  default: false,
                  description: 'Include historical trend summary.'
                }
              }
            }
          }
        ]
      };
    });

    // 2. Handle Tool Calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.totalInvocations++;
      const { name, arguments: args = {} } = request.params;

      try {
        switch (name) {
          // --- PILLAR 1: ZERO-BLOAT GATEWAY ---
          case 'route_tool': {
            const parsed = RouteToolSchema.parse(args);
            const routeResult = await semanticRouter.route(parsed);

            if (parsed.executeImmediately && routeResult.executed) {
              this.dualWriteAuditEvent({
                toolName: routeResult.matchedTool || 'route_tool',
                callerId: 'semantic-router',
                category: ActionCategory.GENERIC,
                decision: PolicyDecision.ALLOW,
                dangerScore: 0,
                severity: SeverityLevel.SAFE,
                reasons: [routeResult.reasoning || `Executed immediately via semantic router`],
                rawPayload: parsed.toolArguments
              });
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      routeResult
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'virtualize_context': {
            const parsed = VirtualizeContextSchema.parse(args);
            const handle = contextVirtualizer.virtualize(parsed);

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      handle
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          // --- PILLAR 2: SWARM PRE-FLIGHT SAFETY ---
          case 'simulate_swarm_impact': {
            const parsed = SimulateSwarmImpactSchema.parse(args);
            const result = await this.swarmNativeEngine.simulate(parsed);

            try {
              dataFlywheel.recordSimulation(result, parsed);
            } catch {
              // Non-blocking flywheel telemetry
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      simulationId: result.simulationId,
                      verdict: result.verdict,
                      prRiskScore: result.prRiskScore,
                      divergenceFromStatic: result.divergenceFromStatic,
                      personasSimulated: result.personasSimulated,
                      findings: result.criticalFindings,
                      heatmap: result.heatmapAscii
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'adversarial_persona_review': {
            const parsed = AdversarialPersonaReviewSchema.parse(args);
            const findings = await this.runPersonaReview(
              parsed.targetDiffOrCommand,
              parsed.personaType,
              parsed.depth
            );

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      personaType: parsed.personaType,
                      depth: parsed.depth,
                      findingsCount: findings.length,
                      findings
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'blast_radius_heatmap': {
            const parsed = BlastRadiusHeatmapSchema.parse(args);
            const simResult = await this.swarmNativeEngine.simulate({
              targetDiffOrCommand: parsed.targetDiffOrCommand,
              contextDescription: 'Heatmap generation'
            });

            const matrix = generateHeatmap(
              parsed.targetDiffOrCommand,
              simResult.criticalFindings,
              simResult.prRiskScore
            );

            let rendered: string | object;
            if (parsed.format === 'ASCII') {
              rendered = renderHeatmapAscii(matrix);
            } else if (parsed.format === 'MARKDOWN') {
              rendered = renderHeatmapMarkdown(matrix);
            } else {
              rendered = matrix;
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      format: parsed.format,
                      overallScore: matrix.overallScore,
                      heatmap: rendered,
                      matrix
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          // --- PILLAR 3: TDD ENFORCER & QUALITY GATE ---
          case 'enforce_tdd_state': {
            const parsed = EnforceTddStateSchema.parse(args);
            let actionResult: any;

            switch (parsed.action) {
              case 'GET_STATE': {
                actionResult = tddStateMachine.getState(parsed.featureName);
                break;
              }
              case 'REGISTER_FAILING_TEST': {
                const testPath = parsed.testFilePath || 'tests/sample.test.ts';
                const details = parsed.testOutput || 'Assertion failed: expected false to be true';
                actionResult = tddStateMachine.registerFailingTest(
                  parsed.featureName,
                  testPath,
                  details
                );
                break;
              }
              case 'VERIFY_TEST_FAILURE': {
                actionResult = tddStateMachine.verifyTestFailure(
                  parsed.featureName,
                  parsed.testOutput || ''
                );
                break;
              }
              case 'VERIFY_TEST_PASS': {
                actionResult = tddStateMachine.verifyTestPass(
                  parsed.featureName,
                  parsed.testOutput || ''
                );
                break;
              }
              case 'RESET': {
                tddStateMachine.reset(parsed.featureName);
                actionResult = tddStateMachine.getState(parsed.featureName);
                break;
              }
              case 'CHECK_PERMISSION': {
                actionResult = tddStateMachine.canModifyProductionCode(
                  parsed.featureName,
                  parsed.targetFilePath || ''
                );
                break;
              }
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      action: parsed.action,
                      featureName: parsed.featureName,
                      result: actionResult,
                      state: tddStateMachine.getState(parsed.featureName)
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'generate_socratic_spec': {
            const parsed = GenerateSocraticSpecSchema.parse(args);
            const spec = generateSocraticSpec(
              parsed.featureRequirement,
              parsed.targetComponents || [],
              parsed.depth
            );

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      spec
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'spawn_worktree_subagent': {
            const parsed = SpawnWorktreeSubagentSchema.parse(args);
            const worktree = await worktreeManager.spawnWorktree(
              parsed.agentId,
              parsed.branchName,
              parsed.baseBranch
            );

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: worktree.status,
                      worktree
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'automated_code_critique': {
            const parsed = AutomatedCodeCritiqueSchema.parse(args);
            const critique = critiqueCode(
              parsed.diffOrCode,
              parsed.filePath,
              parsed.strictSecurity
            );

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      critique
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          // --- PILLAR 4: ZERO-TRUST COMPLIANCE & TELEMETRY ---
          case 'verify_audit_log': {
            const parsed = VerifyAuditLogSchema.parse(args);
            const limit = typeof parsed.limit === 'number' ? parsed.limit : 100;
            const verification = AuditLedger.verifyIntegrity(limit);

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: verification.intact ? 'VERIFIED_INTACT' : 'TAMPER_DETECTED',
                      verification
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'request_confirmation_token': {
            const parsed = RequestConfirmationTokenSchema.parse(args);
            const tokenObj = TokenManager.generateToken(
              parsed.toolName,
              parsed.actionFingerprint,
              parsed.requestedBy,
              parsed.ttlSeconds,
              parsed.reason
            );

            this.dualWriteAuditEvent({
              toolName: 'request_confirmation_token',
              callerId: parsed.requestedBy,
              category: ActionCategory.GENERIC,
              decision: PolicyDecision.REQUIRE_CONFIRMATION,
              dangerScore: 0,
              severity: SeverityLevel.SAFE,
              reasons: [parsed.reason || `Token issued for ${parsed.toolName}`],
              rawPayload: parsed
            });

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'TOKEN_ISSUED',
                      confirmationToken: tokenObj.token,
                      details: tokenObj.payload
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'get_security_posture': {
            const parsed = GetSecurityPostureSchema.parse(args);
            const posture = calculateSecurityPosture({
              activePolicy: this.policyEngine.getPolicy().name,
              totalInvocations: this.totalInvocations,
              blockedCount: this.blockedCount,
              dlpRedactionsCount: this.dlpRedactionsCount,
              criticalAvertedCount: this.criticalAvertedCount
            });

            let responsePayload: any = posture;
            if (parsed.includeHistory) {
              try {
                const flywheelStats = dataFlywheel.getStats();
                responsePayload = {
                  ...posture,
                  historyTrends: flywheelStats
                };
              } catch {
                // Non-blocking telemetry
              }
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(responsePayload, null, 2)
                }
              ]
            };
          }

          // --- LEGACY FOUNDATIONAL TOOLS (PRESERVED FOR BACKWARD COMPATIBILITY) ---
          case 'simulate_action': {
            const command = String(args.commandOrQuery || '');
            const category = args.actionType ? (args.actionType as ActionCategory) : undefined;
            const context = (args.context as Record<string, any>) || {};

            const report = BlastRadiusEngine.evaluate(command, category, context);

            if (report.severity === SeverityLevel.CRITICAL) {
              this.criticalAvertedCount++;
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      simulation: report
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'inspect_payload_dlp': {
            const content = String(args.content || '');
            const maskSensitive = args.maskSensitive !== false;

            const scanResult = DLPScanner.scan(content, maskSensitive);
            if (scanResult.hasFindings) {
              this.dlpRedactionsCount += scanResult.findingsCount;
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'SUCCESS',
                      dlpReport: scanResult
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          case 'enforce_policy': {
            const toolName = String(args.toolName || '');
            const parameters = (args.parameters as Record<string, any>) || {};
            const callerId = String(args.callerId || 'agent-client');
            const confirmationToken = args.confirmationToken ? String(args.confirmationToken) : undefined;

            // 1. Scan parameters for DLP issues
            const serializedParams = JSON.stringify(parameters);
            const dlpScan = DLPScanner.scan(serializedParams, false);

            // 2. Evaluate Blast Radius
            const blastReport = BlastRadiusEngine.evaluate(serializedParams);

            // 3. Evaluate Policy Engine
            const policyResult = this.policyEngine.evaluate(
              toolName,
              parameters,
              blastReport,
              confirmationToken
            );

            if (policyResult.decision === PolicyDecision.BLOCK) {
              this.blockedCount++;
            }

            // 4. Record to cryptographic audit chain and dual-write to flywheel
            const auditEntry = this.dualWriteAuditEvent({
              toolName,
              callerId,
              category: blastReport.category,
              decision: policyResult.decision,
              dangerScore: blastReport.dangerScore,
              severity: blastReport.severity,
              reasons: policyResult.reasons,
              dlpFindingsCount: dlpScan.findingsCount,
              rawPayload: parameters
            });

            // 5. Sequence analysis over the ledger, including the decision just recorded
            const sequence = SequenceDetector.fromPolicy(this.policyConfig).analyzeFromLedger();
            const worstSignal = sequence.signals.reduce<(typeof sequence.signals)[number] | undefined>(
              (acc, s) => {
                if (!acc) return s;
                return severityWeight(s.severity) > severityWeight(acc.severity) ? s : acc;
              },
              undefined
            );
            const escalate =
              worstSignal !== undefined &&
              policyResult.decision === PolicyDecision.ALLOW &&
              worstSignal.recommendedAction !== 'FLAG_FOR_REVIEW';

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: policyResult.decision === PolicyDecision.BLOCK ? 'BLOCKED' : 'PROCEED',
                      decision: escalate ? 'REQUIRE_CONFIRMATION' : policyResult.decision,
                      ruleMatched: policyResult.ruleMatched ?? null,
                      reasons: escalate
                        ? [...policyResult.reasons, `Sequence analysis: ${worstSignal!.reason}`]
                        : policyResult.reasons,
                      requiresToken: escalate || policyResult.requiresToken,
                      tokenValid: policyResult.tokenValid ?? false,
                      blastRadius: {
                        dangerScore: blastReport.dangerScore,
                        severity: blastReport.severity,
                        destructive: blastReport.destructive,
                        reversibility: blastReport.rollbackFeasible ? 'ROLLBACK_FEASIBLE' : 'IRREVERSIBLE',
                        resolvedCommand: blastReport.resolution?.resolvedCommand ?? null,
                        traits: blastReport.resolution?.traits ?? []
                      },
                      dlp: {
                        findingsCount: dlpScan.findingsCount,
                        findings: dlpScan.findings.map((f) => ({
                          type: f.type,
                          category: f.category,
                          preview: f.preview
                        }))
                      },
                      sequence: {
                        analysedEntries: sequence.analysedEntries,
                        truncated: sequence.truncated,
                        highestSeverity: sequence.highestSeverity,
                        signals: sequence.signals.map((s) => ({
                          id: s.id,
                          severity: s.severity,
                          confidence: s.confidence,
                          reason: s.reason,
                          recommendedAction: s.recommendedAction,
                          fromIndex: s.evidence.fromIndex,
                          toIndex: s.evidence.toIndex
                        }))
                      },
                      auditReceipt: {
                        index: auditEntry.index,
                        receiptId: auditEntry.currentHash,
                        signature: auditEntry.signature,
                        timestamp: auditEntry.timestamp
                      }
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          default:
            return {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: `Unknown tool name: ${name}`
                }
              ]
            };
        }
      } catch (err: any) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Internal BlastRadius Error: ${err?.message || String(err)}`
            }
          ]
        };
      }
    });
  }

  public async connect(transport: Transport): Promise<void> {
    await this.server.connect(transport);
  }

  public async close(): Promise<void> {
    await this.server.close();
  }

  public getServer(): Server {
    return this.server;
  }

  public async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.connect(transport);
    console.error('BlastRadius MCP Security Server active on stdio');
  }
}
