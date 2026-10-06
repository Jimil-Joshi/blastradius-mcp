import { z } from 'zod';

export enum SeverityLevel {
  SAFE = 'SAFE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export enum ActionCategory {
  SHELL = 'SHELL',
  SQL = 'SQL',
  CLOUD = 'CLOUD',
  FILESYSTEM = 'FILESYSTEM',
  NETWORK = 'NETWORK',
  GENERIC = 'GENERIC'
}

export enum PolicyDecision {
  ALLOW = 'ALLOW',
  BLOCK = 'BLOCK',
  REQUIRE_CONFIRMATION = 'REQUIRE_CONFIRMATION'
}

export interface BlastRadiusReport {
  dangerScore: number; // 0 to 100
  severity: SeverityLevel;
  category: ActionCategory;
  reasons: string[];
  affectedEntities: string[];
  destructive: boolean;
  irreversible: boolean;
  rollbackFeasible: boolean;
  recommendedMitigations: string[];
  /** What the shell will actually run, after quote removal and expansion. */
  resolution?: {
    resolvedCommand: string;
    traits: string[];
    hasPipeline: boolean;
    interpreters: string[];
    unresolvedVariables: string[];
  };
  dryRunSimulation?: {
    simulatedOutput: string;
    estimatedCostDeltaUsd?: number;
    affectedItemCount: number;
  };
}

export interface DLPFinding {
  type: string;
  category: 'SECRET' | 'PII' | 'CREDENTIAL';
  severity: SeverityLevel;
  preview: string;
  startIndex: number;
  endIndex: number;
}

export interface DLPScanResult {
  hasFindings: boolean;
  findingsCount: number;
  findings: DLPFinding[];
  sanitizedContent: string;
  originalRedactedDiffCount: number;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  action: PolicyDecision;
  severityThreshold?: SeverityLevel;
  category?: ActionCategory;
  forbiddenPatterns?: string[];
  protectedPaths?: string[];
  allowedTools?: string[];
  deniedTools?: string[];
  requireApprovalForDestructive?: boolean;
}

export interface SecurityPolicyConfig {
  version: string;
  name: string;
  description: string;
  defaultDecision: PolicyDecision;
  rules: PolicyRule[];
  allowedDirectories?: string[];
  protectedEnvironments?: string[];
  /**
   * Workflow-level analysis across the audit ledger, for multi-step attacks
   * whose individual calls all pass. Omitted means enabled with defaults.
   */
  /**
   * When true, the blast-radius engine may BLOCK on its own verdict and not only
   * through an explicit rule.
   *
   * Set on the built-in zero-trust policy and off by default for custom policies,
   * because a custom policy is an organisation's explicit statement about what its
   * rules do and do not cover, and silently overriding a disabled rule would make
   * `enabled: false` a lie.
   *
   * Without it, a structured payload whose command is spread across JSON fields
   * (`{command:'rm', args:['-rf','/']}`) scores 100 CRITICAL while every
   * text-matching rule passes, which is the one case text rules cannot reach.
   */
  engineCriticalBlocks?: boolean;

  /** Optional sequence-detection thresholds. See `SequenceDetector`. */
  sequence?: {
    enabled?: boolean;
    windowSize?: number;
    destructiveBurstThreshold?: number;
    probingThreshold?: number;
  };
}

export interface AuditEntry {
  index: number;
  timestamp: string;
  toolName: string;
  callerId: string;
  category: ActionCategory;
  decision: PolicyDecision;
  dangerScore: number;
  severity: SeverityLevel;
  reasons: string[];
  dlpFindingsCount: number;
  inputHash: string;
  prevHash: string;
  currentHash: string;
  signature: string;
}

export interface ApprovalTokenPayload {
  tokenId: string;
  toolName: string;
  actionFingerprint: string;
  requestedBy: string;
  issuedAt: number;
  expiresAt: number;
  reason?: string;
}

export interface ApprovalToken {
  token: string;
  payload: ApprovalTokenPayload;
}

export interface SecurityPostureSummary {
  status: 'ACTIVE' | 'WARNING' | 'ALERT';
  edition: 'open-source';
  totalInvocations: number;
  blockedCount: number;
  dlpRedactionsCount: number;
  criticalAvertedCount: number;
  auditChainIntact: boolean;
  activePolicy: string;
}

// Zod Schemas for Tool Arguments
export const SimulateActionSchema = z.object({
  actionType: z.enum(['SHELL', 'SQL', 'CLOUD', 'FILESYSTEM', 'NETWORK', 'GENERIC']).optional(),
  commandOrQuery: z.string().describe('The command, SQL query, API call, or script to simulate and evaluate'),
  context: z.record(z.string(), z.any()).optional().describe('Optional execution context such as environment (prod/stage), working directory, or target database')
});

export const InspectPayloadDLPSchema = z.object({
  content: z.string().describe('The raw text, code, log, or prompt payload to inspect for secrets, credentials, and PII'),
  maskSensitive: z.boolean().default(true).describe('If true, returns the redacted string with secrets masked'),
  strictMode: z.boolean().default(false).describe('If true, scans with aggressive heuristic patterns')
});

export const EnforcePolicySchema = z.object({
  toolName: z.string().describe('The name of the tool intended to be called'),
  parameters: z.record(z.string(), z.any()).describe('The parameters intended to be passed to the tool'),
  callerId: z.string().optional().default('agent-client').describe('Identifier of the calling agent or user'),
  confirmationToken: z.string().optional().describe('Optional cryptographically signed approval token for elevated execution')
});

export const RequestConfirmationTokenSchema = z.object({
  toolName: z.string().describe('The name of the tool requesting approval'),
  actionFingerprint: z.string().describe('Hash or identifier of the payload/action to approve'),
  requestedBy: z.string().describe('Agent or user requesting elevated execution'),
  ttlSeconds: z.number().min(30).max(3600).default(300).describe('Time-to-live for the token in seconds')
});

export const VerifyAuditLogSchema = z.object({
  limit: z.number().min(1).max(1000).default(100).describe('Number of recent audit entries to verify')
});
