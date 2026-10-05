import { ActionCategory, PolicyDecision, SecurityPolicyConfig, SeverityLevel } from '../types.js';

export const ZERO_TRUST_POLICY: SecurityPolicyConfig = {
  version: '1.0.0',
  name: 'Default Zero-Trust Shield',
  description: 'Blocks critical destructive operations, requires confirmation tokens for high severity actions, and protects sensitive secrets.',
  defaultDecision: PolicyDecision.ALLOW,
  protectedEnvironments: ['prod', 'production', 'live', 'main'],
  allowedDirectories: [],
  rules: [
    {
      id: 'ZT-001',
      name: 'Block Root and Wildcard Deletion',
      description: 'Hard block on commands that purge root or wildcard directories',
      enabled: true,
      action: PolicyDecision.BLOCK,
      forbiddenPatterns: [
        'rm -rf /',
        'rm -rf *',
        'DROP DATABASE',
        'DROP SCHEMA',
        'mkfs',
        'format c:'
      ]
    },
    {
      id: 'ZT-002',
      name: 'Block Fork Bombs and System Overwrites',
      description: 'Hard block on resource exhaustion and raw partition writes',
      enabled: true,
      action: PolicyDecision.BLOCK,
      forbiddenPatterns: [
        ':(){ :|:& };:',
        'dd if=/dev/zero',
        'del /f /s /q c:\\windows'
      ]
    },
    {
      id: 'ZT-003',
      name: 'Require Approval for Critical & High Danger Actions',
      description: 'Actions with danger score >= 70 require cryptographically signed approval token',
      enabled: true,
      action: PolicyDecision.REQUIRE_CONFIRMATION,
      severityThreshold: SeverityLevel.HIGH,
      requireApprovalForDestructive: true
    },
    {
      id: 'ZT-004',
      name: 'Protect Secret & Auth Files',
      description: 'Block direct modification of sensitive credential and environment files',
      enabled: true,
      action: PolicyDecision.BLOCK,
      protectedPaths: [
        '.env',
        '.env.local',
        '.env.production',
        'id_rsa',
        'id_ed25519',
        '.aws/credentials',
        '/etc/shadow',
        'service-account.json'
      ]
    }
  ]
};

export const READ_ONLY_AUDIT_POLICY: SecurityPolicyConfig = {
  version: '1.0.0',
  name: 'Read-Only Audit Guard',
  description: 'Strict policy allowing only non-destructive inspection, queries, and read commands.',
  defaultDecision: PolicyDecision.BLOCK,
  rules: [
    {
      id: 'RO-001',
      name: 'Allow Safe Read Operations',
      description: 'Allows reading files and safe SELECT queries',
      enabled: true,
      action: PolicyDecision.ALLOW,
      severityThreshold: SeverityLevel.SAFE
    }
  ]
};
