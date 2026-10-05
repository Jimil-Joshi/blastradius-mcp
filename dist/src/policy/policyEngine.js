import { PolicyDecision, SeverityLevel } from '../types.js';
import { ZERO_TRUST_POLICY } from './defaultPolicies.js';
import { TokenManager } from '../security/tokenManager.js';
export class PolicyEngine {
    policy;
    constructor(customPolicy) {
        this.policy = customPolicy || ZERO_TRUST_POLICY;
    }
    setPolicy(newPolicy) {
        this.policy = newPolicy;
    }
    getPolicy() {
        return this.policy;
    }
    /**
     * Evaluates a tool request against current policy rules and blast radius report.
     */
    evaluate(toolName, params, blastReport, confirmationToken) {
        const reasons = [];
        const commandText = JSON.stringify(params).toLowerCase();
        // 1. Evaluate explicit BLOCK rules
        for (const rule of this.policy.rules) {
            if (!rule.enabled)
                continue;
            // Check forbidden string patterns
            if (rule.forbiddenPatterns) {
                for (const pattern of rule.forbiddenPatterns) {
                    if (commandText.includes(pattern.toLowerCase())) {
                        reasons.push(`Violates rule [${rule.name}]: Matches strictly forbidden pattern '${pattern}'`);
                        return {
                            decision: PolicyDecision.BLOCK,
                            ruleMatched: rule.id,
                            reasons,
                            requiresToken: false
                        };
                    }
                }
            }
            // Check protected paths
            if (rule.protectedPaths) {
                for (const path of rule.protectedPaths) {
                    if (commandText.includes(path.toLowerCase())) {
                        reasons.push(`Violates rule [${rule.name}]: Accesses protected path '${path}'`);
                        return {
                            decision: PolicyDecision.BLOCK,
                            ruleMatched: rule.id,
                            reasons,
                            requiresToken: false
                        };
                    }
                }
            }
        }
        // 2. Evaluate Severity Thresholds & Confirmation Requirements
        for (const rule of this.policy.rules) {
            if (!rule.enabled)
                continue;
            if (rule.action === PolicyDecision.REQUIRE_CONFIRMATION) {
                const isHighOrCritical = blastReport.severity === SeverityLevel.CRITICAL ||
                    blastReport.severity === SeverityLevel.HIGH;
                if (isHighOrCritical || (rule.requireApprovalForDestructive && blastReport.destructive)) {
                    // If a confirmation token is provided, verify it
                    if (confirmationToken) {
                        const tokenVerification = TokenManager.verifyToken(confirmationToken, toolName);
                        if (tokenVerification.valid) {
                            reasons.push(`Action elevated and approved via valid token: ${tokenVerification.payload?.tokenId}`);
                            return {
                                decision: PolicyDecision.ALLOW,
                                ruleMatched: rule.id,
                                reasons,
                                requiresToken: false,
                                tokenValid: true
                            };
                        }
                        else {
                            reasons.push(`Provided confirmation token is invalid or expired: ${tokenVerification.error}`);
                        }
                    }
                    reasons.push(`Elevated risk (Severity: ${blastReport.severity}, Danger Score: ${blastReport.dangerScore}). Cryptographic confirmation token required to proceed.`);
                    return {
                        decision: PolicyDecision.REQUIRE_CONFIRMATION,
                        ruleMatched: rule.id,
                        reasons,
                        requiresToken: true,
                        tokenValid: false
                    };
                }
            }
        }
        // 3. Fallback to default policy decision
        return {
            decision: this.policy.defaultDecision,
            reasons: reasons.length > 0 ? reasons : ['Complies with all active security baseline rules.'],
            requiresToken: false
        };
    }
}
