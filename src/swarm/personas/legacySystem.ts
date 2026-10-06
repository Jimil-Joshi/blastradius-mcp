import { AdversarialPersona, PersonaFinding } from '../types.js';

/**
 * Legacy System Persona:
 * Simulates stale HTTP headers, deprecated parameters, cache desynchronization,
 * and slow socket timeouts.
 */
export function createLegacySystemPersona(id = 'legacy-01'): AdversarialPersona {
  return {
    id,
    name: 'Legacy System Persona',
    type: 'LEGACY_SYSTEM',
    description: 'Adversarial simulation of legacy upstream/downstream integrations with slow networks, stale caches, and deprecated schemas',
    focusArea: 'DATA_INTEGRITY',
    evaluate(diffOrCommand: string, _context?: Record<string, any>): PersonaFinding[] {
      const findings: PersonaFinding[] = [];
      const cleanCode = diffOrCommand.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // 1. Socket Timeout Hang / Missing Fetch Timeout
      const hasHttpCall = /\b(?:fetch|axios(?:\.get|\.post)?|https?\.request)\s*\(/i.test(cleanCode);
      const hasTimeout = /(?:timeout\s*[:=]|AbortSignal\.timeout|signal\s*:)/i.test(cleanCode);

      if (hasHttpCall && !hasTimeout) {
        findings.push({
          personaType: 'LEGACY_SYSTEM',
          attackVector: 'SOCKET_TIMEOUT_HANG',
          description: 'Outbound HTTP network call lacks an explicit timeout configuration or AbortSignal. A stalled legacy peer socket can hold connection pools open indefinitely.',
          suggestedTest: 'it("should abort outbound HTTP request if upstream server does not respond within configured timeout")',
          severity: 'MEDIUM',
          reproductionSteps: [
            'Simulate slow upstream HTTP socket that accepts connection but sends 0 bytes',
            'Trigger outbound client request',
            'Verify request aborts cleanly within 5000ms instead of hanging process'
          ],
          affectedEntity: 'Network'
        });
      }

      // 2. Cache Desynchronization / Missing Cache Invalidation
      const hasDbMutation =
        /(?:db\.(?:\w+\.)?(?:update|delete|save)|User\.update|users\.update|db\.query\s*\(\s*['"`]UPDATE)/i.test(cleanCode);
      const hasCacheInvalidation =
        /(?:cache|redis)\s*\.\s*(?:del|set|evict|invalidate|clear|setex)|revalidateTag|revalidatePath/i.test(cleanCode);

      if (hasDbMutation && !hasCacheInvalidation) {
        findings.push({
          personaType: 'LEGACY_SYSTEM',
          attackVector: 'CACHE_DESYNCHRONIZATION',
          description: 'Database entity update or deletion performs mutation without corresponding cache invalidation, resulting in stale reads from downstream cache layers.',
          suggestedTest: 'it("should evict or refresh cached record after successful entity mutation")',
          severity: 'MEDIUM',
          reproductionSteps: [
            'Warm the cache by requesting target record',
            'Execute mutation to update target record attributes',
            'Query record immediately from read replica/cache and verify update is reflected'
          ],
          affectedEntity: 'Storage'
        });
      }

      // 3. Deprecated Schema Breakage / Backward Compatibility Break
      const enforcesNewCamelCaseOnly =
        /const\s+\w*[uU]serId\s*=\s*req\.body\.userId/i.test(diffOrCommand) &&
        /if\s*\(!\w*[uU]serId\)\s*throw/i.test(diffOrCommand);

      const supportsLegacySnakeCase = /user_id|req\.body\['user_id'\]/i.test(diffOrCommand);

      if (enforcesNewCamelCaseOnly && !supportsLegacySnakeCase) {
        findings.push({
          personaType: 'LEGACY_SYSTEM',
          attackVector: 'DEPRECATED_SCHEMA_BREAKAGE',
          description: 'API handler rejects legacy snake_case parameter names (e.g. user_id) without backward compatibility fallback, breaking existing legacy clients.',
          suggestedTest: 'it("should accept both legacy snake_case and camelCase parameters during deprecation grace period")',
          severity: 'MEDIUM',
          reproductionSteps: [
            'Send legacy client request containing snake_case payload {"user_id": "123"}',
            'Observe API error or validation failure',
            'Verify server accepts legacy format and maps to internal representation'
          ],
          affectedEntity: 'APIs'
        });
      }

      // 4. Stale Headers / Missing Content-Type Negotiation
      const assumesJsonBody =
        /req\.body\b/i.test(diffOrCommand) &&
        !/headers\['content-type'\]|is\('json'\)|validateContentType/i.test(diffOrCommand);

      if (assumesJsonBody && /handleRaw|parseBody/i.test(diffOrCommand)) {
        findings.push({
          personaType: 'LEGACY_SYSTEM',
          attackVector: 'STALE_HEADERS',
          description: 'Endpoint assumes modern Content-Type application/json without handling legacy urlencoded or text encodings sent by older proxies.',
          suggestedTest: 'it("should negotiate Content-Type header gracefully or return 415 Unsupported Media Type")',
          severity: 'LOW',
          reproductionSteps: [
            'Send request with Content-Type: application/x-www-form-urlencoded',
            'Verify handler parses or safely rejects with HTTP 415'
          ],
          affectedEntity: 'APIs'
        });
      }

      return findings;
    }
  };
}
