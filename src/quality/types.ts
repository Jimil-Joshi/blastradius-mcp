/**
 * BlastRadius-Zero Quality Gate & TDD Types
 */

export enum TddPhase {
  IDLE = 'IDLE',
  RED_PENDING = 'RED_PENDING',
  RED_CONFIRMED = 'RED_CONFIRMED',
  GREEN_PENDING = 'GREEN_PENDING',
  REFACTOR = 'REFACTOR'
}

export interface TddStateContext {
  activeFeature: string;
  phase: TddPhase;
  failingTestPath?: string;
  failingTestAssertion?: string;
  greenVerificationTimestamp?: string;
  allowedWritePaths: string[];
  history?: Array<{
    phase: TddPhase;
    timestamp: string;
    details?: string;
  }>;
}

export interface SocraticSpecResult {
  featureName: string;
  summary: string;
  invariants: string[];
  preconditions: string[];
  postconditions: string[];
  edgeCases: Array<{
    scenario: string;
    input: string;
    expectedOutcome: string;
  }>;
  securityRequirements: string[];
  testPlan: Array<{
    testName: string;
    description: string;
    assertionHint: string;
  }>;
  markdownSpec: string;
}

export interface WorktreeResult {
  agentId: string;
  branchName: string;
  worktreePath: string;
  baseBranch: string;
  status: 'CREATED' | 'ACTIVE' | 'CLEANED' | 'FAILED';
  createdAt: string;
  message?: string;
}

export interface CodeCritiqueFinding {
  ruleId: string;
  category: 'SECURITY' | 'QUALITY' | 'ERROR_HANDLING' | 'PERFORMANCE' | 'STYLE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  filePath?: string;
  lineNumber?: number;
  lineContent?: string;
  message: string;
  suggestion: string;
}

export interface CodeCritiqueResult {
  score: number;
  passed: boolean;
  findingsCount: number;
  findings: CodeCritiqueFinding[];
  summary: string;
  analyzedFiles: string[];
}
