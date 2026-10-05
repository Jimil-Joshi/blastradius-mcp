import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { BlastRadiusEngine } from './analyzer/blastRadiusEngine.js';
import { DLPScanner } from './analyzer/dlpScanner.js';
import { PolicyEngine } from './policy/policyEngine.js';
import { TokenManager } from './security/tokenManager.js';
import { AuditLedger } from './security/auditLedger.js';
import { LicenseValidator } from './security/licenseValidator.js';
import { PolicyDecision, SeverityLevel } from './types.js';
export class BlastRadiusServer {
    server;
    policyEngine;
    totalInvocations = 0;
    blockedCount = 0;
    dlpRedactionsCount = 0;
    criticalAvertedCount = 0;
    constructor() {
        this.policyEngine = new PolicyEngine();
        AuditLedger.initialize();
        this.server = new Server({
            name: 'blastradius-mcp',
            version: '1.0.0'
        }, {
            capabilities: {
                tools: {}
            }
        });
        this.setupHandlers();
    }
    setupHandlers() {
        // 1. List Available Tools
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: 'simulate_action',
                        description: 'Simulates and predicts the blast radius, danger score (0-100), and destructive reversibility of a shell command, SQL query, or cloud operation before execution.',
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
                        description: 'Deep Data Loss Prevention (DLP) scanner. Detects, reports, and redacts API keys, passwords, JWTs, cloud credentials, credit cards, SSNs, and PII from prompts, code, and logs.',
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
                        description: 'The central zero-trust decision point. Evaluates a prospective tool call against organizational security policies, scans parameters for DLP, and records a cryptographic audit trail.',
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
                        description: 'Generates a time-bound, cryptographically signed (HMAC-SHA256) step-up approval token allowing an agent to execute high-impact actions when human consent is granted.',
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
                        description: 'Cryptographically verifies the immutable hash-chained audit ledger to detect tampering, deleted records, or unauthorized log modifications.',
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
                        description: 'Returns current operational security metrics, active policy profile, license tier, blocked threat statistics, and DLP redaction totals.',
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
                        const category = args.actionType ? args.actionType : undefined;
                        const context = args.context || {};
                        const report = BlastRadiusEngine.evaluate(command, category, context);
                        if (report.severity === SeverityLevel.CRITICAL) {
                            this.criticalAvertedCount++;
                        }
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        status: 'SUCCESS',
                                        simulation: report
                                    }, null, 2)
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
                                    text: JSON.stringify({
                                        status: 'SUCCESS',
                                        dlpReport: scanResult
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    case 'enforce_policy': {
                        const toolName = String(args.toolName || '');
                        const parameters = args.parameters || {};
                        const callerId = String(args.callerId || 'agent-client');
                        const confirmationToken = args.confirmationToken ? String(args.confirmationToken) : undefined;
                        // 1. Scan parameters for DLP issues
                        const serializedParams = JSON.stringify(parameters);
                        const dlpScan = DLPScanner.scan(serializedParams, false);
                        // 2. Evaluate Blast Radius
                        const blastReport = BlastRadiusEngine.evaluate(serializedParams);
                        // 3. Evaluate Policy Engine
                        const policyResult = this.policyEngine.evaluate(toolName, parameters, blastReport, confirmationToken);
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
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        status: policyResult.decision === PolicyDecision.BLOCK ? 'BLOCKED' : 'PROCEED',
                                        decision: policyResult.decision,
                                        reasons: policyResult.reasons,
                                        requiresToken: policyResult.requiresToken,
                                        blastRadius: {
                                            dangerScore: blastReport.dangerScore,
                                            severity: blastReport.severity,
                                            destructive: blastReport.destructive,
                                            reversibility: blastReport.rollbackFeasible ? 'ROLLBACK_FEASIBLE' : 'IRREVERSIBLE'
                                        },
                                        dlp: {
                                            findingsCount: dlpScan.findingsCount,
                                            findings: dlpScan.findings.map((f) => ({
                                                type: f.type,
                                                category: f.category,
                                                preview: f.preview
                                            }))
                                        },
                                        auditReceipt: {
                                            index: auditEntry.index,
                                            receiptId: auditEntry.currentHash,
                                            signature: auditEntry.signature,
                                            timestamp: auditEntry.timestamp
                                        }
                                    }, null, 2)
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
                        const tokenObj = TokenManager.generateToken(toolName, actionFingerprint, requestedBy, ttlSeconds, reason);
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        status: 'TOKEN_ISSUED',
                                        confirmationToken: tokenObj.token,
                                        details: tokenObj.payload
                                    }, null, 2)
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
                                    text: JSON.stringify({
                                        status: verification.intact ? 'VERIFIED_INTACT' : 'TAMPER_DETECTED',
                                        verification
                                    }, null, 2)
                                }
                            ]
                        };
                    }
                    case 'get_security_posture': {
                        const license = LicenseValidator.getStatus();
                        const auditCheck = AuditLedger.verifyIntegrity(50);
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        status: this.blockedCount > 10 ? 'ALERT' : 'ACTIVE',
                                        licenseTier: license.tier,
                                        licensedFeatures: license.features,
                                        metrics: {
                                            totalInvocations: this.totalInvocations,
                                            blockedCount: this.blockedCount,
                                            dlpRedactionsCount: this.dlpRedactionsCount,
                                            criticalAvertedCount: this.criticalAvertedCount
                                        },
                                        auditLedger: {
                                            intact: auditCheck.intact,
                                            recordedEntries: auditCheck.totalEntries
                                        },
                                        activePolicy: this.policyEngine.getPolicy().name
                                    }, null, 2)
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
            }
            catch (err) {
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
    async start() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('BlastRadius MCP Security Server active on stdio');
    }
}
