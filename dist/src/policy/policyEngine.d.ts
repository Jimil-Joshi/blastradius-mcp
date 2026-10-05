import { BlastRadiusReport, PolicyDecision, SecurityPolicyConfig } from '../types.js';
export interface PolicyEvaluationResult {
    decision: PolicyDecision;
    ruleMatched?: string;
    reasons: string[];
    requiresToken: boolean;
    tokenValid?: boolean;
}
export declare class PolicyEngine {
    private policy;
    constructor(customPolicy?: SecurityPolicyConfig);
    setPolicy(newPolicy: SecurityPolicyConfig): void;
    getPolicy(): SecurityPolicyConfig;
    /**
     * Evaluates a tool request against current policy rules and blast radius report.
     */
    evaluate(toolName: string, params: Record<string, any>, blastReport: BlastRadiusReport, confirmationToken?: string): PolicyEvaluationResult;
}
