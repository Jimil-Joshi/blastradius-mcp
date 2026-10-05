import { z } from 'zod';
export var SeverityLevel;
(function (SeverityLevel) {
    SeverityLevel["SAFE"] = "SAFE";
    SeverityLevel["LOW"] = "LOW";
    SeverityLevel["MEDIUM"] = "MEDIUM";
    SeverityLevel["HIGH"] = "HIGH";
    SeverityLevel["CRITICAL"] = "CRITICAL";
})(SeverityLevel || (SeverityLevel = {}));
export var ActionCategory;
(function (ActionCategory) {
    ActionCategory["SHELL"] = "SHELL";
    ActionCategory["SQL"] = "SQL";
    ActionCategory["CLOUD"] = "CLOUD";
    ActionCategory["FILESYSTEM"] = "FILESYSTEM";
    ActionCategory["NETWORK"] = "NETWORK";
    ActionCategory["GENERIC"] = "GENERIC";
})(ActionCategory || (ActionCategory = {}));
export var PolicyDecision;
(function (PolicyDecision) {
    PolicyDecision["ALLOW"] = "ALLOW";
    PolicyDecision["BLOCK"] = "BLOCK";
    PolicyDecision["REQUIRE_CONFIRMATION"] = "REQUIRE_CONFIRMATION";
})(PolicyDecision || (PolicyDecision = {}));
export var LicenseTier;
(function (LicenseTier) {
    LicenseTier["COMMUNITY"] = "COMMUNITY";
    LicenseTier["PRO"] = "PRO";
    LicenseTier["ENTERPRISE"] = "ENTERPRISE";
})(LicenseTier || (LicenseTier = {}));
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
