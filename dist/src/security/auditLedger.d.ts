import { ActionCategory, AuditEntry, PolicyDecision, SeverityLevel } from '../types.js';
export declare class AuditLedger {
    private static ledgerPath;
    private static entries;
    private static lastHash;
    private static secretKey;
    static initialize(customFilePath?: string): void;
    /**
     * Append a new audit record to the cryptographic hash chain.
     */
    static record(params: {
        toolName: string;
        callerId: string;
        category: ActionCategory;
        decision: PolicyDecision;
        dangerScore: number;
        severity: SeverityLevel;
        reasons: string[];
        dlpFindingsCount: number;
        rawPayload: any;
    }): AuditEntry;
    /**
     * Cryptographically verifies the entire chain or a recent window of entries.
     * Returns whether the chain is unbroken and untampered.
     */
    static verifyIntegrity(limit?: number): {
        intact: boolean;
        totalEntries: number;
        verifiedCount: number;
        tamperedIndex?: number;
        error?: string;
    };
    static getEntries(limit?: number): AuditEntry[];
    static reset(): void;
}
