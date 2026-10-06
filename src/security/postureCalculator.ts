import { getEdition } from './edition.js';
import { AuditLedger } from './auditLedger.js';
import { DataFlywheel, dataFlywheel } from '../storage/flywheel.js';
import {
  PostureTelemetryInput,
  SecurityPosture,
  FlywheelStats
} from '../storage/types.js';

export { PostureTelemetryInput, SecurityPosture };

export class PostureCalculator {
  public static calculate(input: PostureTelemetryInput = {}): SecurityPosture {
    const edition = getEdition();

    let auditIntact: boolean;
    let auditTampered: boolean;
    let auditTotalEntries: number = 0;
    let auditError: string | undefined;

    if (input.auditChainIntact !== undefined) {
      auditIntact = input.auditChainIntact;
      auditTampered = !auditIntact;
      auditTotalEntries = 0;
      if (!auditIntact) {
        auditError = 'Audit log chain integrity failure or tampering detected';
      }
    } else {
      const auditCheck = AuditLedger.verifyIntegrity(50);
      auditIntact = auditCheck.intact;
      auditTampered = !auditCheck.intact;
      auditTotalEntries = auditCheck.totalEntries;
      auditError = auditCheck.error;
    }

    const totalInvocations = input.totalInvocations ?? 0;
    const blockedCount = input.blockedCount ?? 0;
    const dlpRedactionsCount = input.dlpRedactionsCount ?? 0;
    const criticalAvertedCount = input.criticalAvertedCount ?? 0;
    const activePolicy = input.activePolicy ?? 'Default Zero-Trust Shield';

    let flywheelStats: FlywheelStats;
    if (input.flywheel) {
      flywheelStats = input.flywheel.getStats();
    } else if (input.flywheelStats) {
      flywheelStats = input.flywheelStats;
    } else {
      try {
        flywheelStats = dataFlywheel.getStats();
      } catch {
        flywheelStats = {
          totalSimulations: 0,
          attackVectorsLearned: 0,
          enhancementsApplied: 0,
          pendingEnhancements: 0,
          averageRiskScore: 0,
          topAttackVectors: []
        };
      }
    }

    // Compute Overall Security Posture Score (0-100, 100 = most secure)
    let score = 100;

    // Tampered audit chain is a critical violation
    if (!auditIntact) {
      score -= 50;
    }

    // Deduct for blocked malicious/risky invocations
    if (blockedCount > 0) {
      score -= Math.min(25, blockedCount * 5);
    }

    // Deduct for DLP redactions (indicates leakage exposure)
    if (dlpRedactionsCount > 0) {
      score -= Math.min(15, dlpRedactionsCount * 3);
    }

    // Telemetry impact from simulation flywheel
    if (flywheelStats.totalSimulations > 0) {
      if (flywheelStats.averageRiskScore >= 70) {
        score -= 15;
      } else if (flywheelStats.averageRiskScore >= 40) {
        score -= 5;
      }

      if (flywheelStats.pendingEnhancements > 0) {
        score -= Math.min(10, flywheelStats.pendingEnhancements * 2);
      }

      if (flywheelStats.enhancementsApplied > 0) {
        // Bonus for active defenses applied
        score = Math.min(100, score + Math.min(10, flywheelStats.enhancementsApplied * 2));
      }
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    // Status: ACTIVE | WARNING | ALERT
    let status: 'ACTIVE' | 'WARNING' | 'ALERT' = 'ACTIVE';
    if (!auditIntact || score < 50 || blockedCount > 10) {
      status = 'ALERT';
    } else if (score < 80 || blockedCount > 0 || flywheelStats.pendingEnhancements > 0) {
      status = 'WARNING';
    }

    return {
      overallScore: score,
      score,
      status,
      edition: edition.edition,
      license: edition.license,
      licenseKeyRequired: edition.licenseKeyRequired,
      rateLimited: edition.rateLimited,
      capabilities: edition.capabilities,
      activePolicy,
      metrics: {
        totalInvocations,
        blockedCount,
        dlpRedactionsCount,
        criticalAvertedCount
      },
      auditChain: {
        intact: auditIntact,
        tampered: auditTampered,
        totalEntries: auditTotalEntries,
        error: auditError
      },
      auditLedger: {
        intact: auditIntact,
        recordedEntries: auditTotalEntries
      },
      flywheel: flywheelStats
    };
  }
}

export function calculateSecurityPosture(input: PostureTelemetryInput = {}): SecurityPosture {
  return PostureCalculator.calculate(input);
}
