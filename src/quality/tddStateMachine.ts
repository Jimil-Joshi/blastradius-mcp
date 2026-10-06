/**
 * BlastRadius-Zero TDD State Machine
 * Enforces Red -> Green -> Refactor discipline before allowing production code changes.
 */

import { TddPhase, TddStateContext } from './types.js';

export class TddStateMachine {
  private static instance?: TddStateMachine;
  private stateMap: Map<string, TddStateContext> = new Map();

  public static getInstance(): TddStateMachine {
    if (!TddStateMachine.instance) {
      TddStateMachine.instance = new TddStateMachine();
    }
    return TddStateMachine.instance;
  }

  /**
   * Returns current TDD state context for a given feature.
   * If feature is untracked, initializes it in IDLE phase.
   */
  public getState(featureName: string): TddStateContext {
    let state = this.stateMap.get(featureName);
    if (!state) {
      state = {
        activeFeature: featureName,
        phase: TddPhase.IDLE,
        allowedWritePaths: [],
        history: [
          {
            phase: TddPhase.IDLE,
            timestamp: new Date().toISOString(),
            details: `Initialized TDD state for feature: ${featureName}`
          }
        ]
      };
      this.stateMap.set(featureName, state);
    }
    return state;
  }

  /**
   * Registers a failing test for the active feature.
   * Transitions phase to RED_PENDING.
   */
  public registerFailingTest(
    featureName: string,
    testFilePath: string,
    assertionDetails: string
  ): TddStateContext {
    const state = this.getState(featureName);
    state.phase = TddPhase.RED_PENDING;
    state.failingTestPath = testFilePath;
    state.failingTestAssertion = assertionDetails;

    if (!state.allowedWritePaths.includes(testFilePath)) {
      state.allowedWritePaths.push(testFilePath);
    }

    state.history?.push({
      phase: TddPhase.RED_PENDING,
      timestamp: new Date().toISOString(),
      details: `Registered failing test: ${testFilePath} (${assertionDetails})`
    });

    return state;
  }

  /**
   * Verifies that the test output indicates actual test failure.
   * On confirmation, transitions phase to RED_CONFIRMED.
   */
  public verifyTestFailure(
    featureName: string,
    testOutput: string
  ): { verified: boolean; message: string; state: TddStateContext } {
    const state = this.getState(featureName);

    const hasFailure = this.detectFailureSignals(testOutput);

    if (hasFailure) {
      state.phase = TddPhase.RED_CONFIRMED;
      state.history?.push({
        phase: TddPhase.RED_CONFIRMED,
        timestamp: new Date().toISOString(),
        details: 'Verified test failure in output. Transitioned to RED_CONFIRMED.'
      });

      return {
        verified: true,
        message: 'Failing test verified successfully (RED phase confirmed). You may now modify production code.',
        state
      };
    }

    return {
      verified: false,
      message: 'Test output did not indicate any test failure. State remains RED_PENDING.',
      state
    };
  }

  /**
   * Verifies that the test output indicates all tests pass.
   * Requires previous phase to be RED_CONFIRMED or GREEN_PENDING.
   * On success, transitions to REFACTOR.
   */
  public verifyTestPass(
    featureName: string,
    testOutput: string
  ): { verified: boolean; message: string; state: TddStateContext } {
    const state = this.getState(featureName);

    if (state.phase !== TddPhase.RED_CONFIRMED && state.phase !== TddPhase.GREEN_PENDING) {
      return {
        verified: false,
        message: 'Cannot verify test pass: RED phase must be confirmed before GREEN verification.',
        state
      };
    }

    const hasFailure = this.detectFailureSignals(testOutput);
    if (hasFailure) {
      return {
        verified: false,
        message: 'Test output contains failures; cannot verify pass.',
        state
      };
    }

    const hasPass = this.detectPassSignals(testOutput);
    if (!hasPass) {
      return {
        verified: false,
        message: 'Test output did not confirm test suite success.',
        state
      };
    }

    state.phase = TddPhase.REFACTOR;
    state.greenVerificationTimestamp = new Date().toISOString();
    state.history?.push({
      phase: TddPhase.REFACTOR,
      timestamp: state.greenVerificationTimestamp,
      details: 'Verified test suite pass. Transitioned to REFACTOR.'
    });

    return {
      verified: true,
      message: 'All tests passed successfully (GREEN phase confirmed). Proceed to REFACTOR.',
      state
    };
  }

  /**
   * Explicitly starts the implementation phase (transitions RED_CONFIRMED to GREEN_PENDING).
   */
  public startGreenPhase(featureName: string): TddStateContext {
    const state = this.getState(featureName);
    if (state.phase === TddPhase.RED_CONFIRMED) {
      state.phase = TddPhase.GREEN_PENDING;
      state.history?.push({
        phase: TddPhase.GREEN_PENDING,
        timestamp: new Date().toISOString(),
        details: 'Started implementation (GREEN_PENDING phase).'
      });
    }
    return state;
  }

  /**
   * Evaluates if modifying a given file path is allowed under current TDD phase.
   */
  public canModifyProductionCode(
    featureName: string,
    targetFilePath: string
  ): { allowed: boolean; reason?: string } {
    if (this.isTestFile(targetFilePath)) {
      return { allowed: true };
    }

    const state = this.getState(featureName);
    if (state.phase === TddPhase.IDLE || state.phase === TddPhase.RED_PENDING) {
      return {
        allowed: false,
        reason: 'Agent cannot modify production code until a failing test is written and confirmed (RED phase)'
      };
    }

    // Automatically transition to GREEN_PENDING when production code modification begins
    if (state.phase === TddPhase.RED_CONFIRMED) {
      state.phase = TddPhase.GREEN_PENDING;
      state.history?.push({
        phase: TddPhase.GREEN_PENDING,
        timestamp: new Date().toISOString(),
        details: 'Production code modification started: transitioned to GREEN_PENDING.'
      });
    }

    return { allowed: true };
  }

  /**
   * Resets TDD state for a feature back to IDLE.
   */
  public reset(featureName: string): void {
    this.stateMap.delete(featureName);
  }

  /**
   * Heuristic to determine if a target path is test/spec code vs production code.
   * Requires explicit directory or delimiter boundaries to prevent stem collisions
   * (e.g. contestant.ts, spectator.ts, perspective.ts).
   */
  public isTestFile(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, '/').toLowerCase();
    return (
      /(^|\/)(test|tests|spec|specs|__tests__|__specs__)\//i.test(normalized) ||
      /(\.|\b|_|-)(test|spec)\.[a-z0-9]+$/i.test(normalized) ||
      /(^|\/)(test|spec)[_\.-][a-z0-9_-]+\.[a-z0-9]+$/i.test(normalized)
    );
  }

  private detectFailureSignals(output: string): boolean {
    const lines = output.split(/\r?\n/);

    // Filter out lines that are confirmed pass assertions or summaries
    const passLineRegex = /^\s*(?:✔|✓|ok\b|PASS\b|\+)\s+/i;
    const nonPassLines: string[] = [];

    for (const line of lines) {
      if (!passLineRegex.test(line)) {
        nonPassLines.push(line);
      }
    }

    const nonPassText = nonPassLines.join('\n');

    const strongFailure =
      /AssertionError/i.test(nonPassText) ||
      /ERR_ASSERTION/i.test(nonPassText) ||
      /exited with code [1-9]/i.test(nonPassText) ||
      /\bnot ok\b/i.test(nonPassText) ||
      /[✖×]/i.test(nonPassText) ||
      /expected\s+.*\s+to\s+(?:equal|be|match|include|have)/i.test(nonPassText) ||
      /\b(?:stack trace|Error:)/i.test(nonPassText);

    if (strongFailure) {
      return true;
    }

    // Strip out zero-failure tokens like "fail 0", "0 fail", "0 failures", "failures: 0"
    const cleaned = nonPassText.replace(
      /(?:0\s+fail(?:ed|ures)?|fail(?:ed|ures)?(?::|\s+)\s*0|0\s+errors|errors(?::|\s+)\s*0)/gi,
      ''
    );

    const generalFailure = /\b(?:fail|failed|failure|failures)\b/i.test(cleaned);
    return generalFailure;
  }

  private detectPassSignals(output: string): boolean {
    const passIndicators =
      /\b(?:pass|passed|ok|success)\b/i.test(output) ||
      /✔/i.test(output) ||
      /all tests passed/i.test(output) ||
      /(?:fail|failed|failures):\s*0/i.test(output) ||
      /0\s+fail(?:ed|ures)?/i.test(output);

    return passIndicators;
  }
}

export const tddStateMachine = TddStateMachine.getInstance();
