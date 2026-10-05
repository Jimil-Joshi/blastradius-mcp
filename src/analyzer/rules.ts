import { ActionCategory, SeverityLevel } from '../types.js';

export interface RuleSignature {
  id: string;
  category: ActionCategory;
  pattern: RegExp;
  dangerScore: number;
  severity: SeverityLevel;
  reason: string;
  destructive: boolean;
  irreversible: boolean;
  mitigations: string[];
}

export const DANGEROUS_RULES: RuleSignature[] = [
  // --- SHELL RULES ---
  {
    id: 'SH-001',
    category: ActionCategory.SHELL,
    pattern: /\brm\s+(-[rfRF]{1,4}\s+)?(\/|\*|~|\$HOME|\.\/|\.\.)(\s|$)/,
    dangerScore: 100,
    severity: SeverityLevel.CRITICAL,
    reason: 'Recursive root, home, or wildcard filesystem deletion detected (rm -rf / or *)',
    destructive: true,
    irreversible: true,
    mitigations: ['Target specific named directories only', 'Use trash-cli or create a verified dry-run backup first']
  },
  {
    id: 'SH-002',
    category: ActionCategory.SHELL,
    pattern: /\b(mkfs|dd\s+if=.*of=\/dev\/|fdisk|parted)\b/,
    dangerScore: 100,
    severity: SeverityLevel.CRITICAL,
    reason: 'Raw disk formatting, block device overwrite, or partition modification detected',
    destructive: true,
    irreversible: true,
    mitigations: ['Execute storage operations only through cloud control planes with snapshots']
  },
  {
    id: 'SH-003',
    category: ActionCategory.SHELL,
    pattern: /(:\{\s*:\|\s*:&\s*\};:|\b(fork\s*bomb)\b)/,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Fork bomb / resource exhaustion exploit pattern detected',
    destructive: true,
    irreversible: false,
    mitigations: ['Enforce process limits (ulimit -u) and isolate compute']
  },
  {
    id: 'SH-004',
    category: ActionCategory.SHELL,
    pattern: /\b(curl|wget|fetch|invoke-webrequest)\b.*\|\s*(bash|sh|zsh|powershell|pwsh)\b/i,
    dangerScore: 90,
    severity: SeverityLevel.HIGH,
    reason: 'Unverified remote script piped directly into shell execution (curl | sh)',
    destructive: false,
    irreversible: false,
    mitigations: ['Download script, verify SHA-256 checksum, inspect contents before execution']
  },
  {
    id: 'SH-005',
    category: ActionCategory.SHELL,
    pattern: /\bchmod\s+(-R\s+)?(777|666|a\+rwx)\b/,
    dangerScore: 80,
    severity: SeverityLevel.HIGH,
    reason: 'Permissive permission change (chmod 777) introduces critical privilege vulnerabilities',
    destructive: false,
    irreversible: false,
    mitigations: ['Use principle of least privilege (e.g., chmod 750 or 644)']
  },
  {
    id: 'SH-006',
    category: ActionCategory.SHELL,
    pattern: /\b(shutdown|reboot|poweroff|init\s+0|halt)\b/i,
    dangerScore: 85,
    severity: SeverityLevel.HIGH,
    reason: 'System halt, reboot, or shutdown command invoked',
    destructive: true,
    irreversible: false,
    mitigations: ['Ensure maintenance windows are scheduled and system restart authorized']
  },
  {
    id: 'SH-007',
    category: ActionCategory.SHELL,
    pattern: /\bgit\s+(push\s+.*--force|reset\s+--hard|clean\s+-[fF]dx)/i,
    dangerScore: 85,
    severity: SeverityLevel.HIGH,
    reason: 'Destructive git command (force push, hard reset, or untracked file purge) risks code loss',
    destructive: true,
    irreversible: true,
    mitigations: ['Use git branch backup before hard reset; use git push --force-with-lease']
  },
  {
    id: 'SH-008',
    category: ActionCategory.SHELL,
    pattern: /\b(reg\s+delete|del\s+\/f\s+\/s\s+\/q\s+[c-zC-Z]:\\windows)/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Windows system registry deletion or System32 file destruction attempted',
    destructive: true,
    irreversible: true,
    mitigations: ['Never execute system-level registry modifications without restore point']
  },

  // --- SQL RULES ---
  {
    id: 'SQL-001',
    category: ActionCategory.SQL,
    pattern: /\bDROP\s+(DATABASE|SCHEMA)\b/i,
    dangerScore: 100,
    severity: SeverityLevel.CRITICAL,
    reason: 'DROP DATABASE or SCHEMA causes irreversible destruction of entire databases',
    destructive: true,
    irreversible: true,
    mitigations: ['Ensure point-in-time recovery (PITR) is active; require multi-party approval']
  },
  {
    id: 'SQL-002',
    category: ActionCategory.SQL,
    pattern: /\b(DROP|TRUNCATE)\s+TABLE\b/i,
    dangerScore: 90,
    severity: SeverityLevel.CRITICAL,
    reason: 'DROP or TRUNCATE TABLE purges table schema and all contained data immediately',
    destructive: true,
    irreversible: true,
    mitigations: ['Take table snapshot / backup before dropping; soft-delete or rename first']
  },
  {
    id: 'SQL-003',
    category: ActionCategory.SQL,
    pattern: /\bDELETE\s+FROM\s+["`\w.]+\s*(;|\s*$)/i,
    dangerScore: 90,
    severity: SeverityLevel.CRITICAL,
    reason: 'Unbounded DELETE statement without a WHERE clause will delete all rows',
    destructive: true,
    irreversible: true,
    mitigations: ['Specify explicit WHERE condition with primary keys; wrap in transaction']
  },
  {
    id: 'SQL-004',
    category: ActionCategory.SQL,
    pattern: /\bUPDATE\s+["`\w.]+\s+SET\s+[^;]+(?<!WHERE[^;]+);?\s*$/i,
    dangerScore: 85,
    severity: SeverityLevel.HIGH,
    reason: 'Unbounded UPDATE statement without WHERE clause will overwrite entire column data',
    destructive: true,
    irreversible: true,
    mitigations: ['Add WHERE clause or test inside BEGIN TRANSACTION ... ROLLBACK first']
  },
  {
    id: 'SQL-005',
    category: ActionCategory.SQL,
    pattern: /\bGRANT\s+ALL\s+PRIVILEGES\b/i,
    dangerScore: 80,
    severity: SeverityLevel.HIGH,
    reason: 'Excessive database privilege grant (GRANT ALL PRIVILEGES) violates least privilege',
    destructive: false,
    irreversible: false,
    mitigations: ['Grant specific permissions (SELECT, INSERT, UPDATE) on designated tables only']
  },

  // --- CLOUD RULES (AWS, GCP, AZURE, K8S) ---
  {
    id: 'CLD-001',
    category: ActionCategory.CLOUD,
    pattern: /\b(terminate-instances|delete-cluster|delete-db-instance|delete-bucket|delete-stack)\b/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Cloud resource termination (EC2, RDS, S3, or EKS) will destroy infrastructure',
    destructive: true,
    irreversible: true,
    mitigations: ['Verify backup snapshots exist and resource termination protection is disabled deliberately']
  },
  {
    id: 'CLD-002',
    category: ActionCategory.CLOUD,
    pattern: /\bkubectl\s+(delete\s+(namespace|all|nodes|pv|pvc)|drain)\b/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Kubernetes cluster-wide deletion (namespace, node, or PVC destruction)',
    destructive: true,
    irreversible: true,
    mitigations: ['Isolate to dev/test namespaces; never run against kube-system or default in prod']
  },
  {
    id: 'CLD-003',
    category: ActionCategory.CLOUD,
    pattern: /\b(delete-user|delete-role|detach-role-policy|delete-access-key)\b/i,
    dangerScore: 85,
    severity: SeverityLevel.HIGH,
    reason: 'Cloud IAM entity deletion risks breaking critical service authentication',
    destructive: true,
    irreversible: true,
    mitigations: ['Deactivate credentials first before permanent deletion']
  },

  // --- FILESYSTEM SENSITIVE RULES ---
  {
    id: 'FS-001',
    category: ActionCategory.FILESYSTEM,
    pattern: /(\.env|\.aws\/credentials|\.ssh\/id_rsa|\/etc\/shadow|\/etc\/passwd|service-account.*\.json)\b/i,
    dangerScore: 80,
    severity: SeverityLevel.HIGH,
    reason: 'Direct access or modification to sensitive credentials or system auth files',
    destructive: false,
    irreversible: false,
    mitigations: ['Use vault secret references instead of raw credential files']
  }
];
