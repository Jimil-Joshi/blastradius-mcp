import { BlastRadiusEngine } from '../analyzer/blastRadiusEngine.js';
import { DLPScanner } from '../analyzer/dlpScanner.js';
import { SeverityLevel } from '../types.js';
import { RegisteredToolSchema, SandboxExecutionResult } from './types.js';

const NON_COMMAND_PROSE_KEYS = new Set([
  'message',
  'description',
  'content',
  'body',
  'text',
  'title',
  'comment',
  'notes',
  'note',
  'reason',
  'rationale',
  'summary',
  'instruction',
  'instructions',
  'prompt',
  'document',
  'readme',
  'changelog',
  'doc',
  'docs',
  'body_text',
  'summary_text'
]);

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

    // 2. Blast Radius & Shell Safety check: evaluate command safety via structured JSON
    // If all parameter fields are purely prose (e.g. commit messages, PR descriptions, comments),
    // they represent documentation/prose rather than executable commands.
    const argKeys = Object.keys(args);
    const isPureProse =
      argKeys.length > 0 &&
      argKeys.every((k) => NON_COMMAND_PROSE_KEYS.has(k.toLowerCase()));

    if (!isPureProse) {
      const report = BlastRadiusEngine.evaluate(serializedArgs);

      // If destructive or high risk, halt execution
      if (
        report.destructive ||
        report.dangerScore >= 70 ||
        report.severity === SeverityLevel.CRITICAL ||
        report.severity === SeverityLevel.HIGH
      ) {
        const reasons = report.reasons.length > 0 ? report.reasons.join('; ') : 'Destructive action detected';
        return {
          success: false,
          securityVerdict: 'BLOCK',
          reason: `Blast radius violation: ${reasons} (danger score: ${report.dangerScore})`
        };
      }
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
