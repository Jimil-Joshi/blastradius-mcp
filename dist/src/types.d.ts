import { z } from 'zod';
export declare enum SeverityLevel {
    SAFE = "SAFE",
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH",
    CRITICAL = "CRITICAL"
}
export declare enum ActionCategory {
    SHELL = "SHELL",
    SQL = "SQL",
    CLOUD = "CLOUD",
    FILESYSTEM = "FILESYSTEM",
    NETWORK = "NETWORK",
    GENERIC = "GENERIC"
}
export declare enum PolicyDecision {
    ALLOW = "ALLOW",
    BLOCK = "BLOCK",
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
}
export declare enum LicenseTier {
    COMMUNITY = "COMMUNITY",
    PRO = "PRO",
    ENTERPRISE = "ENTERPRISE"
}
export interface BlastRadiusReport {
    dangerScore: number;
    severity: SeverityLevel;
    category: ActionCategory;
    reasons: string[];
    affectedEntities: string[];
    destructive: boolean;
    irreversible: boolean;
    rollbackFeasible: boolean;
    recommendedMitigations: string[];
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
    activeTier: LicenseTier;
    totalInvocations: number;
    blockedCount: number;
    dlpRedactionsCount: number;
    criticalAvertedCount: number;
    auditChainIntact: boolean;
    activePolicy: string;
}
export declare const SimulateActionSchema: z.ZodObject<{
    actionType: z.ZodOptional<z.ZodEnum<{
        CLOUD: "CLOUD";
        FILESYSTEM: "FILESYSTEM";
        GENERIC: "GENERIC";
        NETWORK: "NETWORK";
        SHELL: "SHELL";
        SQL: "SQL";
    }>>;
    commandOrQuery: z.ZodString;
    context: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
}, z.core.$strip>;
export declare const InspectPayloadDLPSchema: z.ZodObject<{
    content: z.ZodString;
    maskSensitive: z.ZodDefault<z.ZodBoolean>;
    strictMode: z.ZodDefault<z.ZodBoolean>;
}, z.core.$strip>;
export declare const EnforcePolicySchema: z.ZodObject<{
    toolName: z.ZodString;
    parameters: z.ZodRecord<z.ZodString, z.ZodAny>;
    callerId: z.ZodDefault<z.ZodOptional<z.ZodString>>;
    confirmationToken: z.ZodOptional<z.ZodString>;
}, z.core.$strip>;
export declare const RequestConfirmationTokenSchema: z.ZodObject<{
    toolName: z.ZodString;
    actionFingerprint: z.ZodString;
    requestedBy: z.ZodString;
    ttlSeconds: z.ZodDefault<z.ZodNumber>;
}, z.core.$strip>;
export declare const VerifyAuditLogSchema: z.ZodObject<{
    limit: z.ZodDefault<z.ZodNumber>;
}, z.core.$strip>;
