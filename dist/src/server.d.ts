export declare class BlastRadiusServer {
    private server;
    private policyEngine;
    private totalInvocations;
    private blockedCount;
    private dlpRedactionsCount;
    private criticalAvertedCount;
    constructor();
    private setupHandlers;
    start(): Promise<void>;
}
