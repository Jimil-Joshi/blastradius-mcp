import { ActionCategory, BlastRadiusReport, SeverityLevel } from '../types.js';
import { DANGEROUS_RULES } from './rules.js';

export class BlastRadiusEngine {
  /**
   * Automatically detect the category of an action if not explicitly provided.
   */
  public static inferCategory(content: string): ActionCategory {
    const trimmed = content.trim();
    if (/^(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE)\b/i.test(trimmed)) {
      return ActionCategory.SQL;
    }
    if (/\b(aws|gcloud|az|kubectl|terraform|helm)\b/i.test(trimmed)) {
      return ActionCategory.CLOUD;
    }
    if (/\b(rm|cp|mv|chmod|chown|touch|mkdir|cat|ls|pwd|grep|awk|sed|curl|wget|npm|pip|git|powershell|bash|sh)\b/i.test(trimmed)) {
      return ActionCategory.SHELL;
    }
    if (/\b(open|read|write|unlink|mkdir|rmdir|copyFile|writeFile)\b/i.test(trimmed)) {
      return ActionCategory.FILESYSTEM;
    }
    if (/\b(https?:\/\/|connect|ping|traceroute|nmap|netstat|ssh|scp)\b/i.test(trimmed)) {
      return ActionCategory.NETWORK;
    }
    return ActionCategory.GENERIC;
  }

  /**
   * Evaluates blast radius, danger score, and generates a simulation report.
   */
  public static evaluate(
    commandOrQuery: string,
    explicitCategory?: ActionCategory,
    context?: Record<string, any>
  ): BlastRadiusReport {
    const category = explicitCategory || this.inferCategory(commandOrQuery);
    const normalizedInput = commandOrQuery.trim();

    let maxScore = 0;
    const reasons: string[] = [];
    const mitigations = new Set<string>();
    const affectedEntities = new Set<string>();
    let isDestructive = false;
    let isIrreversible = false;

    // 1. Check against predefined signature rules
    for (const rule of DANGEROUS_RULES) {
      if (rule.pattern.test(normalizedInput)) {
        if (rule.dangerScore > maxScore) {
          maxScore = rule.dangerScore;
        }
        reasons.push(rule.reason);
        if (rule.destructive) isDestructive = true;
        if (rule.irreversible) isIrreversible = true;
        rule.mitigations.forEach((m) => mitigations.add(m));
      }
    }

    // 2. Extract potential affected targets (files, tables, cloud targets)
    this.extractAffectedTargets(normalizedInput, category, affectedEntities);

    // 3. Environmental escalation (e.g., prod context increases risk)
    const env = (context?.environment || context?.env || '').toString().toLowerCase();
    const isProduction = ['prod', 'production', 'live', 'main'].includes(env);

    if (isProduction && maxScore > 20) {
      maxScore = Math.min(100, maxScore + 20);
      reasons.push(`Target environment is marked as PRODUCTION (${env}), escalating blast radius.`);
      mitigations.add('Require multi-factor authorization and shadow dry-run prior to production execution.');
    }

    // If safe with no matches
    if (maxScore === 0) {
      maxScore = 5;
      reasons.push('Standard read-only or low-impact routine action.');
      mitigations.add('Proceed under standard monitoring.');
    }

    // Determine severity level from score
    let severity: SeverityLevel;
    if (maxScore >= 90) {
      severity = SeverityLevel.CRITICAL;
    } else if (maxScore >= 70) {
      severity = SeverityLevel.HIGH;
    } else if (maxScore >= 40) {
      severity = SeverityLevel.MEDIUM;
    } else if (maxScore >= 15) {
      severity = SeverityLevel.LOW;
    } else {
      severity = SeverityLevel.SAFE;
    }

    // Feasibility of rollback
    const rollbackFeasible = !isIrreversible && maxScore < 90;

    // Dry-run simulation data
    const simulatedOutput = isDestructive
      ? `[DRY-RUN SIMULATION]: Destructive action simulated. Affected entities: ${Array.from(affectedEntities).join(', ') || 'Global/Broad'}. Execution would permanently alter persistent state.`
      : `[DRY-RUN SIMULATION]: Safe/Read operation verified. No permanent state alteration detected.`;

    return {
      dangerScore: maxScore,
      severity,
      category,
      reasons,
      affectedEntities: Array.from(affectedEntities),
      destructive: isDestructive,
      irreversible: isIrreversible,
      rollbackFeasible,
      recommendedMitigations: Array.from(mitigations),
      dryRunSimulation: {
        simulatedOutput,
        affectedItemCount: affectedEntities.size || (isDestructive ? 1 : 0)
      }
    };
  }

  private static extractAffectedTargets(
    input: string,
    category: ActionCategory,
    entities: Set<string>
  ): void {
    if (category === ActionCategory.SQL) {
      const tableMatch = input.match(/\b(?:FROM|INTO|UPDATE|TABLE)\s+[`"']?([a-zA-Z0-9_.-]+)[`"']?/i);
      if (tableMatch && tableMatch[1]) {
        entities.add(`table:${tableMatch[1]}`);
      }
      const dbMatch = input.match(/\bDATABASE\s+[`"']?([a-zA-Z0-9_.-]+)[`"']?/i);
      if (dbMatch && dbMatch[1]) {
        entities.add(`database:${dbMatch[1]}`);
      }
    } else if (category === ActionCategory.SHELL || category === ActionCategory.FILESYSTEM) {
      const pathMatches = input.matchAll(/(?:\s|^)([\/~.][a-zA-Z0-9_.\-\/\\]+|[a-zA-Z]:\\[a-zA-Z0-9_.\-\/\\]+)/g);
      for (const m of pathMatches) {
        if (m[1] && m[1].length > 1) {
          entities.add(`path:${m[1]}`);
        }
      }
    } else if (category === ActionCategory.CLOUD) {
      const resMatch = input.match(/--(?:instance-ids|bucket|cluster-name|role-name|stack-name)\s+([a-zA-Z0-9_-]+)/i);
      if (resMatch && resMatch[1]) {
        entities.add(`cloud_resource:${resMatch[1]}`);
      }
    }
  }
}
