import { spawn, ChildProcess } from 'node:child_process';
import * as readline from 'node:readline';
import { BlastRadiusEngine } from '../analyzer/blastRadiusEngine.js';
import { DLPScanner } from '../analyzer/dlpScanner.js';
import { PolicyEngine } from '../policy/policyEngine.js';
import { AuditLedger } from '../security/auditLedger.js';
import { PolicyDecision, SeverityLevel } from '../types.js';

export class MCPProxyGateway {
  private downstreamCmd: string;
  private downstreamArgs: string[];
  private childProcess?: ChildProcess;
  private policyEngine: PolicyEngine;

  constructor(commandString: string) {
    const parts = commandString.trim().split(/\s+/);
    this.downstreamCmd = parts[0];
    this.downstreamArgs = parts.slice(1);
    this.policyEngine = new PolicyEngine();
    AuditLedger.initialize();
  }

  public start(): void {
    console.error(`[BlastRadius Gateway] Launching downstream process: ${this.downstreamCmd} ${this.downstreamArgs.join(' ')}`);

    this.childProcess = spawn(this.downstreamCmd, this.downstreamArgs, {
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: true
    });

    if (!this.childProcess.stdin || !this.childProcess.stdout) {
      console.error('[BlastRadius Gateway] Failed to open stdio streams for child process');
      process.exit(1);
    }

    // Readline interfaces for JSON-RPC lines
    const clientReader = readline.createInterface({
      input: process.stdin,
      terminal: false
    });

    const downstreamReader = readline.createInterface({
      input: this.childProcess.stdout,
      terminal: false
    });

    // Handle requests from AI Client (Claude Desktop / Cursor)
    clientReader.on('line', (line: string) => {
      this.handleClientLine(line);
    });

    // Handle responses from Downstream Server
    downstreamReader.on('line', (line: string) => {
      this.handleDownstreamLine(line);
    });

    this.childProcess.on('exit', (code: number | null) => {
      console.error(`[BlastRadius Gateway] Downstream process exited with code ${code}`);
      process.exit(code || 0);
    });
  }

  private handleClientLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const msg = JSON.parse(trimmed);

      // Check if it's a tools/call request
      if (msg.method === 'tools/call') {
        const toolName = msg.params?.name || 'unknown_tool';
        const toolArgs = msg.params?.arguments || {};

        // 1. DLP Scan on inbound arguments
        const dlpScan = DLPScanner.scan(JSON.stringify(toolArgs), false);

        // 2. Blast Radius simulation
        const blastReport = BlastRadiusEngine.evaluate(JSON.stringify(toolArgs));

        // 3. Policy evaluation
        const policyResult = this.policyEngine.evaluate(toolName, toolArgs, blastReport);

        // 4. Record to cryptographic audit chain
        const audit = AuditLedger.record({
          toolName,
          callerId: 'proxy-agent-client',
          category: blastReport.category,
          decision: policyResult.decision,
          dangerScore: blastReport.dangerScore,
          severity: blastReport.severity,
          reasons: policyResult.reasons,
          dlpFindingsCount: dlpScan.findingsCount,
          rawPayload: toolArgs
        });

        // 5. Block if policy forbids
        if (policyResult.decision === PolicyDecision.BLOCK) {
          console.error(`[BlastRadius BLOCKED] ${toolName} blocked. Reason: ${policyResult.reasons.join(', ')}`);
          const blockedResponse = {
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code: -32000,
              message: `[BlastRadius Security Guard] Action BLOCKED by policy. Violations: ${policyResult.reasons.join(' | ')}. Audit receipt: ${audit.currentHash}`
            }
          };
          process.stdout.write(JSON.stringify(blockedResponse) + '\n');
          return;
        }

        // If step-up confirmation required and missing
        if (policyResult.decision === PolicyDecision.REQUIRE_CONFIRMATION) {
          console.error(`[BlastRadius REQUIRE_CONFIRMATION] ${toolName} requires confirmation token.`);
          const confirmResponse = {
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code: -32001,
              message: `[BlastRadius Security Guard] High-impact action requires confirmation token. Danger Score: ${blastReport.dangerScore}. Reasons: ${policyResult.reasons.join(' | ')}`
            }
          };
          process.stdout.write(JSON.stringify(confirmResponse) + '\n');
          return;
        }
      }

      // Safe or non-tools/call: Forward directly to downstream
      if (this.childProcess?.stdin) {
        this.childProcess.stdin.write(trimmed + '\n');
      }
    } catch {
      // Non-JSON line: Forward transparently
      if (this.childProcess?.stdin) {
        this.childProcess.stdin.write(trimmed + '\n');
      }
    }
  }

  private handleDownstreamLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const msg = JSON.parse(trimmed);

      // Sanitize outbound responses: Mask any accidentally leaked credentials or PII
      if (msg.result) {
        const serialized = JSON.stringify(msg.result);
        const scan = DLPScanner.scan(serialized, true);
        if (scan.hasFindings) {
          msg.result = JSON.parse(scan.sanitizedContent);
          console.error(`[BlastRadius DLP] Redacted ${scan.findingsCount} leaked credential(s)/PII from tool output.`);
        }
      }

      process.stdout.write(JSON.stringify(msg) + '\n');
    } catch {
      process.stdout.write(trimmed + '\n');
    }
  }
}
