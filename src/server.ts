import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
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

/** Ordinal severity ordering, so a signal can be compared against a decision. */
function severityWeight(severity: SeverityLevel): number {
  return [SeverityLevel.SAFE, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    .indexOf(severity);
}
import { ActionCategory, PolicyDecision, SecurityPolicyConfig, SeverityLevel } from './types.js';

export class BlastRadiusServer {
  private server: Server;
  private policyEngine: PolicyEngine;
  /** Retained so sequence detection honours the same thresholds as the policy. */
  private policyConfig?: SecurityPolicyConfig;
  private totalInvocations = 0;
  private blockedCount = 0;
  private dlpRedactionsCount = 0;
  private criticalAvertedCount = 0;

  constructor(customPolicy?: SecurityPolicyConfig) {
    this.policyConfig = customPolicy;
    this.policyEngine = new PolicyEngine(customPolicy);
    AuditLedger.initialize();

    this.server = new Server(
      {
        name: 'blastradius-mcp',
        version: '1.0.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // 1. List Available Tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'simulate_action',
            description:
              'Simulates and predicts the blast radius, danger score (0-100), and destructive reversibility of a shell command, SQL query, or cloud operation before execution.',
            inputSchema: {
              type: 'object',
              properties: {
                commandOrQuery: {
                  type: 'string',
                  description: 'The shell command, SQL query, or cloud API call to simulate.'
                },
                actionType: {
                  type: 'string',
                  enum: ['SHELL', 'SQL', 'CLOUD', 'FILESYSTEM', 'NETWORK', 'GENERIC'],
                  description: 'Optional action category hint.'
                },
                context: {
                  type: 'object',
                  description: 'Execution context such as environment (prod/stage), working directory, or target host.'
                }
              },
              required: ['commandOrQuery']
            }
          },
          {
            name: 'inspect_payload_dlp',
            description:
              'Deep Data Loss Prevention (DLP) scanner. Detects, reports, and redacts API keys, passwords, JWTs, cloud credentials, credit cards, SSNs, and PII from prompts, code, and logs.',
            inputSchema: {
              type: 'object',
              properties: {
                content: {
                  type: 'string',
                  description: 'The raw text, code snippet, or log output to inspect.'
                },
                maskSensitive: {
                  type: 'boolean',
                  default: true,
                  description: 'Whether to return a sanitized version with credentials and PII masked.'
                }
              },
              required: ['content']
            }
          },
          {
            name: 'enforce_policy',
            description:
              'The central zero-trust decision point. Evaluates a prospective tool call against organizational security policies, scans parameters for DLP, and records a cryptographic audit trail.',
            inputSchema: {
              type: 'object',
              properties: {
                toolName: {
                  type: 'string',
                  description: 'The name of the target tool intended to be called.'
                },
                parameters: {
                  type: 'object',
                  description: 'The parameters intended to be passed to the tool.'
                },
                callerId: {
                  type: 'string',
                  default: 'agent-client',
                  description: 'Unique identifier for the calling agent or user.'
                },
                confirmationToken: {
                  type: 'string',
                  description: 'Optional cryptographically signed approval token for elevated destructive actions.'
                }
              },
              required: ['toolName', 'parameters']
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
            name: 'get_security_posture',
            description:
              'Returns current operational security metrics, the active policy profile, build edition and capabilities, blocked threat statistics, and DLP redaction totals.',
            inputSchema: {
              type: 'object',
              properties: {}
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

            // 4. Record to cryptographic audit chain
            const auditEntry = AuditLedger.record({
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

            // Dual-write to flywheel database for live compliance telemetry
            try {
              dataFlywheel.recordAuditEvent({
                toolName,
                callerId,
                decision: policyResult.decision,
                riskScore: blastReport.dangerScore,
                hash: auditEntry.currentHash
              });
            } catch {
              // Non-blocking telemetry dual-write
            }

            // 5. Sequence analysis over the ledger, including the decision just
            // recorded. A workflow assembled from individually permitted steps is
            // invisible to any single-call rule, so this runs after the per-call
            // verdict and can only tighten it.
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

          case 'request_confirmation_token': {
            const toolName = String(args.toolName || '');
            const actionFingerprint = String(args.actionFingerprint || '');
            const requestedBy = String(args.requestedBy || 'admin');
            const ttlSeconds = typeof args.ttlSeconds === 'number' ? args.ttlSeconds : 300;
            const reason = args.reason ? String(args.reason) : undefined;

            const tokenObj = TokenManager.generateToken(
              toolName,
              actionFingerprint,
              requestedBy,
              ttlSeconds,
              reason
            );

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

          case 'verify_audit_log': {
            const limit = typeof args.limit === 'number' ? args.limit : 100;
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

          case 'get_security_posture': {
            const posture = calculateSecurityPosture({
              activePolicy: this.policyEngine.getPolicy().name,
              totalInvocations: this.totalInvocations,
              blockedCount: this.blockedCount,
              dlpRedactionsCount: this.dlpRedactionsCount,
              criticalAvertedCount: this.criticalAvertedCount
            });

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(posture, null, 2)
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

  public async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('BlastRadius MCP Security Server active on stdio');
  }
}
