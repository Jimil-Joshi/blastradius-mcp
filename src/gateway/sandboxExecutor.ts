import { BlastRadiusEngine } from '../analyzer/blastRadiusEngine.js';
import { DLPScanner } from '../analyzer/dlpScanner.js';
import { SeverityLevel } from '../types.js';
import { RegisteredToolSchema, SandboxExecutionResult } from './types.js';

export class SandboxExecutor {
  /**
   * Safely executes an MCP tool within the BlastRadius security sandbox.
   * Performs DLP scanning for credentials and BlastRadiusEngine checks for
   * dangerous commands and shell injection before dispatch.
   */
  public async execute(
    tool: RegisteredToolSchema,
    args: Record<string, any> = {}
  ): Promise<SandboxExecutionResult> {
    const serializedArgs = JSON.stringify(args);

    // 1. DLP Scan: Check arguments for sensitive credentials, tokens, or PII
    const dlpResult = DLPScanner.scan(serializedArgs);
    if (dlpResult.hasFindings) {
      const hasSevereLeakedSecrets = dlpResult.findings.some(
        (f) =>
          f.category === 'CREDENTIAL' ||
          f.category === 'SECRET' ||
          f.severity === SeverityLevel.CRITICAL ||
          f.severity === SeverityLevel.HIGH
      );

      if (hasSevereLeakedSecrets) {
        const types = Array.from(new Set(dlpResult.findings.map((f) => f.type))).join(', ');
        return {
          success: false,
          securityVerdict: 'BLOCK',
          reason: `DLP violation: Detected credential or sensitive secret in arguments (${types})`
        };
      }
    }

    // 2. Blast Radius & Shell Safety check: evaluate command safety
    const structuredReport = BlastRadiusEngine.evaluate(serializedArgs);
    let worstReport = structuredReport;

    // Additionally evaluate any string leaves directly in case structured leaf is wrapped
    for (const val of Object.values(args)) {
      if (typeof val === 'string' && val.trim().length > 0) {
        const leafReport = BlastRadiusEngine.evaluate(val);
        if (leafReport.dangerScore > worstReport.dangerScore) {
          worstReport = leafReport;
        }
      }
    }

    // If destructive or high risk, halt execution
    if (
      worstReport.destructive ||
      worstReport.dangerScore >= 70 ||
      worstReport.severity === SeverityLevel.CRITICAL ||
      worstReport.severity === SeverityLevel.HIGH
    ) {
      const reasons = worstReport.reasons.length > 0 ? worstReport.reasons.join('; ') : 'Destructive action detected';
      return {
        success: false,
        securityVerdict: 'BLOCK',
        reason: `Blast radius violation: ${reasons} (danger score: ${worstReport.dangerScore})`
      };
    }

    // 3. Dispatch safe execution: use registered handler or simulate safe result
    try {
      if (typeof tool.handler === 'function') {
        const handlerResult = await tool.handler(args);
        return {
          success: true,
          securityVerdict: 'ALLOW',
          result: handlerResult
        };
      }

      return {
        success: true,
        securityVerdict: 'ALLOW',
        result: {
          status: 'simulated_success',
          tool: tool.name,
          executedWith: args,
          timestamp: new Date().toISOString()
        }
      };
    } catch (err: any) {
      return {
        success: false,
        securityVerdict: 'ALLOW',
        reason: `Tool execution failed: ${err?.message || String(err)}`
      };
    }
  }
}

export const sandboxExecutor = new SandboxExecutor();
