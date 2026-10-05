#!/usr/bin/env node
import * as fs from 'node:fs';
import { BlastRadiusServer } from './server.js';
import { MCPProxyGateway } from './proxy/mcpProxy.js';
import { PolicyEngine } from './policy/policyEngine.js';
import { SecurityPolicyConfig } from './types.js';

function printHelp(): void {
  console.log(`
BlastRadius MCP - Zero-Trust Security, Blast Radius Simulation, & DLP Proxy
==========================================================================

Usage:
  npx blastradius-mcp                  Run as a standalone MCP Security Server (stdio)
  npx blastradius-mcp proxy --command  Run as a transparent proxy wrapping another MCP server
  
Options:
  --command, -c <cmd>     Downstream MCP server command to wrap and inspect (proxy mode)
  --policy, -p <file>     Path to custom JSON security policy config
  --help, -h              Show this help message
  --version, -v           Show version information

Environment Variables:
  BLAST_RADIUS_LICENSE_KEY  License key for Pro or Enterprise features (ENT-..., PRO-...)
  BLAST_RADIUS_SIGNING_KEY  Custom secret for signing cryptographic approval tokens
  BLAST_RADIUS_AUDIT_KEY    Custom secret for cryptographic audit log hash chaining

Examples:
  # Run directly with Claude Desktop or Cursor:
  npx blastradius-mcp

  # Wrap a bash or filesystem server with zero-trust guardrails:
  npx blastradius-mcp proxy --command "npx -y @modelcontextprotocol/server-filesystem C:\\workspace"
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log('blastradius-mcp v1.0.0');
    process.exit(0);
  }

  // Load custom policy if specified
  const policyIdx = args.findIndex((arg: string) => arg === '--policy' || arg === '-p');
  let customPolicy: SecurityPolicyConfig | undefined;
  if (policyIdx !== -1 && args[policyIdx + 1]) {
    const policyPath = args[policyIdx + 1];
    if (fs.existsSync(policyPath)) {
      try {
        customPolicy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
        console.error(`[BlastRadius] Loaded custom security policy: ${customPolicy?.name}`);
      } catch (err: any) {
        console.error(`[BlastRadius Error] Failed to parse policy file: ${err.message}`);
        process.exit(1);
      }
    } else {
      console.error(`[BlastRadius Error] Policy file not found: ${policyPath}`);
      process.exit(1);
    }
  }

  // Check for proxy mode
  const isProxy = args[0] === 'proxy' || args.includes('--command') || args.includes('-c');
  if (isProxy) {
    const cmdIdx = args.findIndex((arg: string) => arg === '--command' || arg === '-c');
    let targetCommand = '';
    if (cmdIdx !== -1 && args[cmdIdx + 1]) {
      targetCommand = args[cmdIdx + 1];
    } else if (args[1] && !args[1].startsWith('-')) {
      targetCommand = args.slice(1).join(' ');
    }

    if (!targetCommand) {
      console.error('[BlastRadius Error] Proxy mode requires a target downstream command via --command "<cmd>"');
      process.exit(1);
    }

    const gateway = new MCPProxyGateway(targetCommand);
    gateway.start();
    return;
  }

  // Default: Run Standalone MCP Security Server
  const server = new BlastRadiusServer();
  await server.start();
}

main().catch((err) => {
  console.error('[BlastRadius Fatal Error]', err);
  process.exit(1);
});
