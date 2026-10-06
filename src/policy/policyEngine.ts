import { BlastRadiusReport, PolicyDecision, SecurityPolicyConfig, SeverityLevel } from '../types.js';
import { ZERO_TRUST_POLICY } from './defaultPolicies.js';
import { ShellResolver } from '../analyzer/shellResolver.js';
import { TokenManager } from '../security/tokenManager.js';

export interface PolicyEvaluationResult {
  decision: PolicyDecision;
  ruleMatched?: string;
  reasons: string[];
  requiresToken: boolean;
  tokenValid?: boolean;
}

const SEVERITY_ORDER: SeverityLevel[] = [
  SeverityLevel.SAFE,
  SeverityLevel.LOW,
  SeverityLevel.MEDIUM,
  SeverityLevel.HIGH,
  SeverityLevel.CRITICAL
];

/**
 * Ordinal position of a severity level, so thresholds can be compared with >=.
 */
function severityRank(severity: SeverityLevel): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? 0 : index;
}

export class PolicyEngine {
  private policy: SecurityPolicyConfig;

  constructor(customPolicy?: SecurityPolicyConfig) {
    this.policy = customPolicy || ZERO_TRUST_POLICY;
  }

  public setPolicy(newPolicy: SecurityPolicyConfig): void {
    this.policy = newPolicy;
  }

  public getPolicy(): SecurityPolicyConfig {
    return this.policy;
  }

  /**
   * Evaluates a tool request against current policy rules and blast radius report.
   */
  public evaluate(
    toolName: string,
    params: Record<string, any>,
    blastReport: BlastRadiusReport,
    confirmationToken?: string
  ): PolicyEvaluationResult {
    const reasons: string[] = [];

    // Both the serialized request and the shell-resolved form are checked. The
    // resolved form matters: `D=/etc; cat $D/shadow` contains no literal
    // "/etc/shadow", so a substring match on the raw request alone would let the
    // policy gate bypass the same resolution layer the scoring engine uses.
    const serialized = JSON.stringify(params);
    const resolution = ShellResolver.resolve(serialized);
    const commandText = serialized.toLowerCase();
    const resolvedText = resolution.resolved.toLowerCase();

    // 1. Evaluate explicit BLOCK rules
    for (const rule of this.policy.rules) {
      if (!rule.enabled) continue;

      // Check forbidden string patterns
      if (rule.forbiddenPatterns) {
        for (const pattern of rule.forbiddenPatterns) {
          const needle = pattern.toLowerCase();
          if (commandText.includes(needle) || resolvedText.includes(needle)) {
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
          const needle = path.toLowerCase();
          if (commandText.includes(needle) || resolvedText.includes(needle)) {
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
      if (!rule.enabled) continue;

      if (rule.action === PolicyDecision.REQUIRE_CONFIRMATION) {
        // Honour the rule's own severityThreshold; fall back to HIGH, which is
        // the baseline the shipped zero-trust policy relies on.
        const threshold = rule.severityThreshold ?? SeverityLevel.HIGH;
        const meetsThreshold = severityRank(blastReport.severity) >= severityRank(threshold);

        if (meetsThreshold || (rule.requireApprovalForDestructive && blastReport.destructive)) {
          // If a confirmation token is provided, verify it
          if (confirmationToken) {
            const tokenVerification = TokenManager.verifyToken(confirmationToken, toolName);
            if (tokenVerification.valid) {
              // Burn the token the instant it authorises an action. Without this
              // the same token would stay valid for its whole TTL and could be
              // replayed, which would defeat the point of step-up approval.
              const tokenId = tokenVerification.payload?.tokenId;
              if (tokenId) {
                TokenManager.consumeToken(tokenId, tokenVerification.payload?.expiresAt);
              }
              reasons.push(`Action elevated and approved via valid token: ${tokenId}`);
              return {
                decision: PolicyDecision.ALLOW,
                ruleMatched: rule.id,
                reasons,
                requiresToken: false,
                tokenValid: true
              };
            } else {
              reasons.push(`Provided confirmation token is invalid or expired: ${tokenVerification.error}`);
            }
          }

          // A CRITICAL irreversible action must not be downgraded to "needs a token" on
          // the strength of a text match alone.
          if (this.blocksOnEngineVerdict(blastReport)) {
            reasons.push(this.engineFloorReason(blastReport));
            return {
              decision: PolicyDecision.BLOCK,
              ruleMatched: 'ENGINE-FLOOR',
              reasons,
              requiresToken: false
            };
          }

          reasons.push(
            `Elevated risk (Severity: ${blastReport.severity}, Danger Score: ${blastReport.dangerScore}). Cryptographic confirmation token required to proceed.`
          );
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

    // 3. Fallback to default policy decision.
    //
    // The rule loop above matches text; the blast report is the authority on what
    // the call actually does. A structured payload like
    // `{command:'rm', args:['-rf','/']}` contains no `rm -rf /` substring for any
    // forbidden-pattern rule to match, while the engine scores it 100 CRITICAL and
    // irreversible. Without this floor the policy gate would be strictly more
    // permissive than the engine on the same call, which is the wrong direction
    // for the only component that can say no.
    if (this.blocksOnEngineVerdict(blastReport)) {
      reasons.push(this.engineFloorReason(blastReport));
      return {
        decision: PolicyDecision.BLOCK,
        ruleMatched: 'ENGINE-FLOOR',
        reasons,
        requiresToken: false
      };
    }

    return {
      decision: this.policy.defaultDecision,
      reasons: reasons.length > 0 ? reasons : ['Complies with all active security baseline rules.'],
      requiresToken: false
    };
  }

  /**
   * True when the engine's verdict is severe enough that no text rule's silence
   * may be read as permission.
   */
  private blocksOnEngineVerdict(blastReport: BlastRadiusReport): boolean {
    return (
      this.policy.engineCriticalBlocks === true &&
      blastReport.severity === SeverityLevel.CRITICAL &&
      blastReport.destructive === true &&
      blastReport.dangerScore >= 90
    );
  }

  private engineFloorReason(blastReport: BlastRadiusReport): string {
    return (
      `Blocked by engine floor: ${blastReport.severity} severity ${blastReport.dangerScore} ` +
      `with irreversible blast radius. ${blastReport.reasons[0] ?? ''}`.trim()
    );
  }
}
