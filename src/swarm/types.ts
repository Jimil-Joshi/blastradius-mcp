/**
 * BlastRadius-Zero Swarm Pre-Flight Simulation Types
 */

export interface PersonaFinding {
  personaType: string;
  attackVector: string;
  description: string;
  suggestedTest: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reproductionSteps?: string[];
  affectedEntity?: string;
}

export interface SwarmSimulationRequest {
  targetDiffOrCommand: string;
  contextDescription?: string;
  agentCount?: number;
  intensity?: 'FAST' | 'DEEP';
  focusAreas?: Array<'SECURITY' | 'CONCURRENCY' | 'USABILITY' | 'DATA_INTEGRITY'>;
}

export interface SwarmSimulationResult {
  simulationId: string;
  prRiskScore: number;
  verdict: 'SAFE' | 'WARN' | 'BLOCK';
  personasSimulated: number;
  criticalFindings: PersonaFinding[];
  heatmapAscii: string;
  divergenceFromStatic: number;
  durationMs?: number;
  timestamp?: string;
  heatmapMatrix?: HeatmapMatrix;
}

export interface AdversarialPersona {
  id: string;
  name: string;
  type: 'HACKER' | 'CONFUSED_USER' | 'LEGACY_SYSTEM' | 'CONCURRENCY_RACER' | 'DATA_CORRUPTOR' | string;
  description: string;
  focusArea: 'SECURITY' | 'CONCURRENCY' | 'USABILITY' | 'DATA_INTEGRITY' | string;
  evaluate(diffOrCommand: string, context?: Record<string, any>): Promise<PersonaFinding[]> | PersonaFinding[];
}

export interface HeatmapMatrix {
  dimensions: {
    components: string[];
    riskLevels: string[];
  };
  cells: Array<{
    component: string;
    risk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    score: number;
    description: string;
  }>;
  asciiTable: string;
  markdownTable: string;
  overallScore: number;
  userClasses?: Array<{
    userClass: 'Admin' | 'Customer' | 'Guest' | 'Public' | string;
    exposure: 'SAFE' | 'ELEVATED' | 'CRITICAL';
    detail: string;
  }>;
  dataSensitivity?: Array<{
    category: 'Secrets' | 'PII' | 'Internal' | 'Public' | string;
    exposure: 'CONTAINED' | 'ELEVATED' | 'CRITICAL';
    detail: string;
  }>;
  containmentFeasibility?: {
    level: 'HIGH' | 'MEDIUM' | 'LOW';
    rollbackEase: string;
    compensationActions: string[];
  };
}

