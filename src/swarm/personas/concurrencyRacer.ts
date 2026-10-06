import { AdversarialPersona, PersonaFinding } from '../types.js';

/**
 * Concurrency Racer Persona:
 * Simulates parallel state mutations, simultaneous refresh token calls, race conditions,
 * and TOCTOU (Time-of-Check to Time-of-Use) deadlocks.
 */
export function createConcurrencyRacerPersona(id = 'racer-01'): AdversarialPersona {
  return {
    id,
    name: 'Concurrency Racer Persona',
    type: 'CONCURRENCY_RACER',
    description: 'Adversarial agent exploiting asynchronous race conditions, token rotation windows, and non-atomic state mutations',
    focusArea: 'CONCURRENCY',
    evaluate(diffOrCommand: string, _context?: Record<string, any>): PersonaFinding[] {
      const findings: PersonaFinding[] = [];
      const cleanCode = diffOrCommand.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // 1. Simultaneous Refresh Token Calls / Token Rotation Race Condition
      const isTokenRefreshFlow =
        /(?:refreshToken|handleTokenRefresh|token\/refresh|refresh_token)/i.test(cleanCode) &&
        /(?:delete|revoke|remove)/i.test(cleanCode) &&
        /(?:generate|save|set|create|randomUUID)/i.test(cleanCode);

      const hasDistributedLock =
        /mutex|lock|transaction|atomic|SERIALIZABLE|acquireLock/i.test(cleanCode);

      if (isTokenRefreshFlow && !hasDistributedLock) {
        findings.push({
          personaType: 'CONCURRENCY_RACER',
          attackVector: 'CONCURRENT_TOKEN_REFRESH',
          description: 'Refresh token rotation executes non-atomically across asynchronous operations without a concurrency lock. Simultaneous requests using the same token can race, creating multiple valid session tokens or prematurely revoking legitimate active sessions.',
          suggestedTest: 'it("should atomically lock token exchange and reject concurrent refresh requests with the same token")',
          severity: 'HIGH',
          reproductionSteps: [
            'Obtain a valid refresh token',
            'Issue 2 concurrent POST /refresh requests simultaneously via Promise.all()',
            'Observe if both calls succeed or if an inconsistent session state is generated',
            'Verify distributed mutex allows only one rotation while returning 409/401 to parallel attempt'
          ],
          affectedEntity: 'Auth'
        });
      }

      // 2. TOCTOU (Time of Check to Time of Use) Race Condition
      const hasCheckThenAct =
        /if\s*\([^)]*(?:balance\s*>=|quantity\s*>|count\s*>|remaining\s*>|exists)[^)]*\)[\s\S]*?await\s+(?:deduct|sendFunds|withdraw|reserve|update|save)/i.test(cleanCode);

      const hasTransactionOrLock =
        /FOR\s+UPDATE|SERIALIZABLE|runInTransaction|\$transaction|mutex|withLock/i.test(cleanCode);

      if (hasCheckThenAct && !hasTransactionOrLock) {
        findings.push({
          personaType: 'CONCURRENCY_RACER',
          attackVector: 'TOCTOU_RACE_CONDITION',
          description: 'Asynchronous check-then-act pattern: entity state is inspected before an await operation, allowing concurrent requests to pass the condition simultaneously and cause double-spend or overdraft.',
          suggestedTest: 'it("should enforce atomic conditional update or row locking (FOR UPDATE) to prevent TOCTOU race conditions")',
          severity: 'HIGH',
          reproductionSteps: [
            'Set account balance to $100',
            'Issue 2 simultaneous withdrawal requests for $100 each using Promise.all()',
            'Observe whether total balance goes negative (-$100)',
            'Verify transactional isolation blocks the second withdrawal'
          ],
          affectedEntity: 'Database'
        });
      }

      // 3. Unsynchronized Shared Mutable State in Async Scope
      const hasSharedCounter =
        /let\s+\w*(?:count|total|active|pending)\w*\s*=\s*\d+[\s\S]*?\+\+[\s\S]*?await/i.test(diffOrCommand) ||
        /let\s+\w+\s*=\s*0;[\s\S]*?\+\+[\s\S]*?await[\s\S]*?--/i.test(diffOrCommand);

      if (hasSharedCounter && !hasDistributedLock) {
        findings.push({
          personaType: 'CONCURRENCY_RACER',
          attackVector: 'UNSYNCHRONIZED_SHARED_STATE',
          description: 'Global or module-scoped mutable state is modified before and after asynchronous await operations without mutual exclusion, causing corrupted counters during parallel traffic.',
          suggestedTest: 'it("should use atomic primitives or isolated request context rather than global mutable state")',
          severity: 'MEDIUM',
          reproductionSteps: [
            'Spawn 20 parallel async handlers',
            'Wait for all executions to finish',
            'Verify shared counter matches exact expected equilibrium without race desync'
          ],
          affectedEntity: 'APIs'
        });
      }

      return findings;
    }
  };
}
