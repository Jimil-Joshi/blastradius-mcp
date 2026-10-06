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
    pattern: /\brm\s+(-[rfRF]{1,4}\s+)?(\/|\*|~|\$HOME|\$\{HOME[^}]*\}|\$\{!HOME[^}]*\}|\$\{#HOME[^}]*\}|\/UNKNOWN|\bARITH\b|\.\/|\.\.)(\s|$)/,
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
    // The download-and-execute shape, named from the producing side rather than
    // the consuming one. `curl | sh` was the only form scored, so the same bytes
    // arriving through a process substitution or an `eval` read as two unrelated
    // commands.
    //
    // A substitution feeding a sink is not on its own the shape: `eval "$(echo
    // hi)"` is ordinary scripting. What makes it the shape is the substitution
    // carrying a fetch or a decoder, so that is what the second alternative
    // requires.
    pattern: /\b(curl|wget|fetch|iwr|invoke-webrequest|invoke-restmethod)\b[^;\n]*(\|\s*(bash|sh|zsh|powershell|pwsh|python\d?|node|ruby|perl)\b|<\(|>\()|\b(eval|exec|source)\b[^;\n]*(?:\$\(|`)[^;\n]*(\bcurl\b|\bwget\b|\bfetch\b|\bbase64\b|\bb64decode\b|\batob\s*\()|\b(eval|exec|source)\b[^\n]*(<\(|>\()/i,
    dangerScore: 90,
    severity: SeverityLevel.HIGH,
    reason: 'Remote script flows directly into an interpreter without review (curl | sh, eval "$(curl ...)", bash <(curl ...))',
    destructive: false,
    irreversible: false,
    mitigations: ['Download script, verify SHA-256 checksum, inspect contents before execution']
  },
  {
    id: 'SH-009',
    category: ActionCategory.SHELL,
    // A decoder whose output is handed to something that runs it. Decoding alone
    // is routine and is deliberately not matched; the sink is what makes it the
    // download-and-execute shape.
    pattern: /\bbase64\b[^\n]*[ -](-d|--decode|-D)\b[^\n]*(\|\s*(sh|bash|zsh|python\d?|node|ruby|perl)\b|\b(eval|exec|xargs|source)\b)|\b(eval|exec|xargs)\b[^\n]*(\bbase64\b|\bb64decode\b|\batob\s*\(|base64\.b64decode)/i,
    dangerScore: 90,
    severity: SeverityLevel.HIGH,
    reason: 'Decoded payload is piped into or evaluated by a shell, so the executed bytes are absent from the request',
    destructive: false,
    irreversible: false,
    mitigations: ['Decode to a file, read the decoded text, then execute the reviewed file']
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
    // `TABLE` is optional in a TRUNCATE statement, so `psql -c "TRUNCATE users"`
    // has to match too, not just the spelled-out form.
    pattern: /\bDROP\s+TABLE\b|\bTRUNCATE\s+(TABLE\s+)?[`"\w.]/i,
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
  {
    id: 'CLD-004',
    category: ActionCategory.CLOUD,
    pattern: /\b(terraform|pulumi)\s+(destroy|apply)\b|\bapply\s+-auto-approve\b/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Infrastructure-as-code teardown or unattended apply can destroy every managed resource in one command',
    destructive: true,
    irreversible: true,
    mitigations: [
      'Run plan and share the diff before any apply',
      'Scope state and lock the workspace so one agent cannot apply unreviewed changes',
      'Require human sign-off on the plan output, not just on the command'
    ]
  },
  {
    id: 'CLD-005',
    category: ActionCategory.CLOUD,
    pattern: /\b(s3\s+rb|gsutil\s+rm\b.*\s-r\b|az\s+storage\s+(blob|file)\s+delete|blob\s+remove|rm\s+.*s3:\/\/)|\bs3\s+sync\b[^;\n]*--delete\b/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Object storage mass deletion (bucket removal or a syncing delete) destroys data and versions',
    destructive: true,
    irreversible: true,
    mitigations: ['Enable bucket versioning and object lock', 'Dry-run the sync against a scratch prefix first']
  },
  {
    id: 'CLD-006',
    category: ActionCategory.CLOUD,
    pattern: /\bhelm\s+(uninstall|delete)\b|\bkubectl\s+(delete|rollout\s+undo|apply\s+-f\s+\S*delete)\b/i,
    dangerScore: 85,
    severity: SeverityLevel.HIGH,
    reason: 'Kubernetes workload removal or rollback will take running services offline',
    destructive: true,
    irreversible: true,
    mitigations: ['Confirm replica counts and PDBs before removal', 'Pin the previous manifest before deleting']
  },
  {
    id: 'CLD-007',
    category: ActionCategory.CLOUD,
    pattern: /\bnpm\s+publish\b|\btwine\s+upload\b|\bdocker\s+push\b.*(--latest|:latest)\b/i,
    dangerScore: 80,
    severity: SeverityLevel.HIGH,
    reason: 'Publishing to a public package or image registry is irreversible once consumed downstream',
    destructive: false,
    irreversible: true,
    mitigations: ['Publish from CI with provenance attestations, never from an agent session', 'Pin the version and verify the registry scope']
  },

  // --- FILESYSTEM SENSITIVE RULES ---
{
    id: 'FS-001',
    category: ActionCategory.FILESYSTEM,
    pattern: /(\.env|id_rsa|id_ed25519|\.pem|\.aws\/credentials|\.ssh\/|\/etc\/shadow|\/etc\/passwd|service[-_]account\.json|\.npmrc|\.pypirc|\.git-credentials)/i,
    dangerScore: 80,
    severity: SeverityLevel.HIGH,
    reason: 'Access to credential or secret file risks exposing private keys and session tokens',
    destructive: false,
    irreversible: false,
    mitigations: [
      'Use a secrets manager rather than reading credential files into agent context',
      'Redact secrets before they enter the model context window'
    ]
  },
  {
    id: 'FS-002',
    category: ActionCategory.FILESYSTEM,
    // Mass deletion by synchronisation and pruning is the shape that actually
    // appears in incidents. `rsync --delete` removes destination files absent
    // from the source, so a mistyped trailing slash is a silent wipe.
    pattern: /\brsync\b[^;\n]*\s--delete\b|\b(scp|aws\s+s3\s+sync)\b[^;\n]*\s--delete\b|\bdocker\s+(system|volume|image|network)\s+prune\b|\bgit\s+worktree\s+remove\b[^;\n]*--force\b|\btruncate\b[^;\n]*-s\s*0/,
    dangerScore: 90,
    severity: SeverityLevel.CRITICAL,
    reason: 'Synchronisation and pruning tools delete data that is not named in the command',
    destructive: true,
    irreversible: true,
    mitigations: [
      'Run with --dry-run or -n first and read what it intends to remove',
      'Confirm a trailing slash on the source; omitting it inverts the direction of the sync'
    ]
  },
  {
    id: 'DB-001',
    category: ActionCategory.SQL,
    // Destructive operations reached through a client binary rather than a
    // connection string, which is how they usually arrive in an agent session.
    pattern: /\b(redis-cli|mongosh|mongo)\b[^\n]*\b(FLUSHALL|FLUSHDB|dropDatabase|drop)\b|\bmysql\b[^\n]*\bDROP\s+DATABASE\b|\bpsql\b[^\n]*\b(DROP\s+(DATABASE|SCHEMA)|TRUNCATE)\b/i,
    dangerScore: 95,
    severity: SeverityLevel.CRITICAL,
    reason: 'Destructive database operation issued through a client binary rather than a query',
    destructive: true,
    irreversible: true,
    mitigations: ['Take a snapshot, and confirm the connection string points at the intended instance']
  }
];
