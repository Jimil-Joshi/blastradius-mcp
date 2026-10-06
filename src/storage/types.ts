/**
 * BlastRadius-Zero Storage & Compliance Telemetry Types
 */

export interface RuleEnhancementRecord {
  id: string;
  vectorId: string;
  generatedRuleId: string;
  name: string;
  forbiddenPattern: string;
  action: string;
  status: 'PENDING' | 'AUTO_APPLIED' | 'REJECTED' | string;
  createdAt: string;
}

export interface FlywheelStats {
  totalSimulations: number;
  attackVectorsLearned: number;
  enhancementsApplied: number;
  pendingEnhancements: number;
  averageRiskScore: number;
  topAttackVectors: Array<{ vector: string; count: number }>;
}

export interface SimulationRecord {
  id: string;
  targetDiff: string;
  contextDesc: string;
  riskScore: number;
  verdict: string;
  personasCount: number;
  divergence: number;
  createdAt: string;
}

export interface AttackVectorRecord {
  id: string;
  simulationId: string;
  personaType: string;
  attackVector: string;
  severity: string;
  description: string;
  suggestedTest: string;
  reproductionSteps: string;
  createdAt: string;
}

export interface AuditEventRecord {
  id: string;
  toolName: string;
  callerId: string;
  decision: string;
  riskScore: number;
  hash: string;
  createdAt: string;
}

export interface PostureTelemetryInput {
  auditChainIntact?: boolean;
  activePolicy?: string;
  totalInvocations?: number;
  blockedCount?: number;
  dlpRedactionsCount?: number;
  criticalAvertedCount?: number;
  flywheelStats?: FlywheelStats;
  flywheel?: any;
}

export interface SecurityPosture {
  overallScore: number;
  score: number;
  status: 'ACTIVE' | 'WARNING' | 'ALERT';
  edition: 'open-source';
  license: string;
  licenseKeyRequired: boolean;
  rateLimited: boolean;
  capabilities: Record<string, boolean>;
  activePolicy: string;
  metrics: {
    totalInvocations: number;
    blockedCount: number;
    dlpRedactionsCount: number;
    criticalAvertedCount: number;
  };
  auditChain: {
    intact: boolean;
    tampered: boolean;
    totalEntries: number;
    error?: string;
  };
  auditLedger: {
    intact: boolean;
    recordedEntries: number;
  };
  flywheel: FlywheelStats;
}
