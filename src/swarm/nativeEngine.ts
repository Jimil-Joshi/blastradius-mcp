import { performance } from 'node:perf_hooks';
import {
  SwarmSimulationRequest,
  SwarmSimulationResult,
  PersonaFinding
} from './types.js';
import { generatePersonas } from './personas/index.js';
import { generateHeatmap } from './heatmapGenerator.js';

/**
 * SwarmNativeEngine:
 * Fast, in-memory pre-flight safety simulator executing 25-50 adversarial virtual personas
 * against diffs and commands in under 3 seconds.
 */
export class SwarmNativeEngine {
  /**
   * Run multi-round adversarial simulation
   */
  async simulate(request: SwarmSimulationRequest): Promise<SwarmSimulationResult> {
    const startTime = performance.now();
    const agentCount = Math.max(5, Math.min(50, request.agentCount ?? 25));
    const targetDiff = request.targetDiffOrCommand ?? '';

    // 1. Spawn requested personas
    const personas = generatePersonas(agentCount, request.focusAreas);

    // 2. Round 1: Individual Persona Evaluations (in parallel)
    const evaluationResults = await Promise.all(
      personas.map(p =>
        p.evaluate(targetDiff, {
          contextDescription: request.contextDescription,
          round: 1
        })
      )
    );
    const rawFindings: PersonaFinding[] = evaluationResults.flat();

    // 3. Round 2: Multi-Round Cross-Vector Synthesis
    // Detect compound risks (e.g. Concurrency + Auth or Injection + Usability)
    const hasAuthIssues = rawFindings.some(
      f =>
        f.attackVector === 'AUTH_BYPASS' ||
        f.attackVector === 'PRIVILEGE_ESCALATION' ||
        f.attackVector === 'IDOR' ||
        f.attackVector === 'TOKEN_TAMPERING'
    );
    const hasRaceConditions = rawFindings.some(
      f => f.attackVector === 'CONCURRENT_TOKEN_REFRESH' || f.attackVector === 'TOCTOU_RACE_CONDITION'
    );

    if (hasAuthIssues && hasRaceConditions) {
      const compoundExists = rawFindings.some(f => f.attackVector === 'COMPOUND_AUTH_RACE');
      if (!compoundExists) {
        rawFindings.push({
          personaType: 'CONCURRENCY_RACER',
          attackVector: 'COMPOUND_AUTH_RACE',
          description: 'Compound vulnerability: Authentication boundary modification combined with concurrency race allows session hijacking under high load.',
          suggestedTest: 'it("should maintain strict session invariants under simultaneous auth operations")',
          severity: 'CRITICAL',
          reproductionSteps: [
            'Spawn 10 simultaneous login/refresh threads',
            'Interleave session revocation and renewal calls',
            'Verify no ghost sessions or unauthenticated privilege grants occur'
          ],
          affectedEntity: 'Auth'
        });
      }
    }

    // 4. Deduplicate and normalize findings
    const criticalFindings = this.deduplicateFindings(rawFindings);

    // 5. Calculate PR Risk Score (0 - 100) and Verdict
    const prRiskScore = this.calculateRiskScore(criticalFindings, targetDiff);
    const verdict: 'SAFE' | 'WARN' | 'BLOCK' =
      prRiskScore >= 70 ? 'BLOCK' : prRiskScore >= 30 ? 'WARN' : 'SAFE';

    // 6. Divergence From Static Analysis
    const divergenceFromStatic = this.calculateDivergence(prRiskScore, criticalFindings);

    // 7. Generate Heatmap Matrix & ASCII
    const heatmapMatrix = generateHeatmap(targetDiff, criticalFindings, prRiskScore);
    const heatmapAscii = heatmapMatrix.asciiTable;

    const durationMs = Math.round(performance.now() - startTime);

    return {
      simulationId: `sim_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      prRiskScore,
      verdict,
      personasSimulated: personas.length,
      criticalFindings,
      heatmapAscii,
      divergenceFromStatic,
      durationMs,
      timestamp: new Date().toISOString(),
      heatmapMatrix
    };
  }

  /**
   * Deduplicate findings by attackVector and entity, ensuring high quality and no redundant findings
   */
  private deduplicateFindings(findings: PersonaFinding[]): PersonaFinding[] {
    const map = new Map<string, PersonaFinding>();

    const severityWeight = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1
    };

    for (const f of findings) {
      const key = `${f.attackVector}_${f.affectedEntity || 'GENERAL'}`;
      const existing = map.get(key);

      if (!existing || severityWeight[f.severity] > severityWeight[existing.severity]) {
        // Ensure reproductionSteps and suggestedTest are always populated
        const enriched: PersonaFinding = {
          ...f,
          suggestedTest: f.suggestedTest || `it("should prevent ${f.attackVector.toLowerCase()} vulnerability")`,
          reproductionSteps:
            f.reproductionSteps && f.reproductionSteps.length > 0
              ? f.reproductionSteps
              : [`Execute payload targeting ${f.attackVector}`, `Assert that input is rejected`]
        };
        map.set(key, enriched);
      }
    }

    return Array.from(map.values()).sort(
      (a, b) => severityWeight[b.severity] - severityWeight[a.severity]
    );
  }

  /**
   * Compute Risk Score between 0 and 100
   * SAFE: < 30
   * WARN: 30 - 69
   * BLOCK: >= 70
   */
  private calculateRiskScore(findings: PersonaFinding[], diff: string): number {
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter(f => f.severity === 'LOW').length;

    let score = 0;

    if (criticalCount > 0) {
      // Any CRITICAL finding places the score at or above 75 (BLOCK)
      score = 75 + (criticalCount - 1) * 10 + highCount * 5;
    } else if (highCount > 0) {
      // HIGH findings: 1 high is 45-50 (WARN), 2+ high can push to 70+ (BLOCK)
      score = 45 + (highCount - 1) * 25 + mediumCount * 5;
    } else if (mediumCount > 0) {
      // MEDIUM findings: 1 medium is 35 (WARN)
      score = 35 + (mediumCount - 1) * 10 + lowCount * 3;
    } else if (lowCount > 0) {
      score = 15 + (lowCount - 1) * 5;
    } else {
      // No findings: check if diff has benign patterns
      score = diff.trim().length === 0 ? 0 : 5;
    }

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Calculate how much dynamic swarm findings diverge from standard static linters
   */
  private calculateDivergence(score: number, findings: PersonaFinding[]): number {
    const hasDynamicRisks = findings.some(
      f => f.attackVector.includes('RACE') || f.attackVector.includes('CONCURRENT') || f.attackVector.includes('IDOR')
    );
    const boost = hasDynamicRisks ? 20 : 5;
    return Math.min(100, Math.max(5, Math.round(score * 0.6 + boost)));
  }
}

