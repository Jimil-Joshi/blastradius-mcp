import { AdversarialPersona, PersonaFinding } from '../types.js';

/**
 * Confused User Persona:
 * Simulates malformed JSON, out-of-order calls, missing fields, rapid resubmissions,
 * extreme boundaries, and unhandled undefined object access.
 */
export function createConfusedUserPersona(id = 'confused-01'): AdversarialPersona {
  return {
    id,
    name: 'Confused User Persona',
    type: 'CONFUSED_USER',
    description: 'Adversarial agent sending unexpected payloads, missing properties, boundary anomalies, and duplicated requests',
    focusArea: 'USABILITY',
    evaluate(diffOrCommand: string, _context?: Record<string, any>): PersonaFinding[] {
      const findings: PersonaFinding[] = [];
      const cleanCode = diffOrCommand.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // 1. Unhandled Undefined / Missing Optional Chaining
      // Anchored to untrusted payload roots: req.body, req.query, payload, input, data, etc.
      const deepPropertyRegex = /(?:req\.(?:body|query|params)|payload|input|data|params)\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+/g;
      const matches = cleanCode.match(deepPropertyRegex) || [];
      const hasUnprotectedDeepAccess = matches.some(m => !m.includes('?.'));

      if (hasUnprotectedDeepAccess) {
        findings.push({
          personaType: 'CONFUSED_USER',
          attackVector: 'UNHANDLED_UNDEFINED',
          description: 'Deep object property access without optional chaining (?.) or presence validation triggers TypeError crash when optional fields are omitted.',
          suggestedTest: 'it("should gracefully handle payloads missing nested address/profile fields without throwing unhandled exceptions")',
          severity: 'HIGH',
          reproductionSteps: [
            'Send request payload with null or omitted nested object',
            'Verify server returns 400 Bad Request instead of 500 TypeError crash'
          ],
          affectedEntity: 'APIs'
        });
      }

      // 2. Unprotected JSON.parse
      const hasJsonParse = /JSON\.parse\s*\(/i.test(cleanCode);
      const hasTryCatch = /try\s*\{[\s\S]*?JSON\.parse[\s\S]*?\}\s*catch/i.test(cleanCode);

      if (hasJsonParse && !hasTryCatch) {
        findings.push({
          personaType: 'CONFUSED_USER',
          attackVector: 'UNPROTECTED_JSON_PARSE',
          description: 'Synchronous JSON.parse() executed outside of a try/catch block will crash the process or bubble an unhandled SyntaxError on malformed JSON.',
          suggestedTest: 'it("should safely parse or reject invalid JSON string payloads without unhandled crash")',
          severity: 'HIGH',
          reproductionSteps: [
            'Send malformed JSON string (e.g. "{\\"invalid\\": ")',
            'Trigger JSON.parse() execution',
            'Confirm application handles parsing error gracefully'
          ],
          affectedEntity: 'APIs'
        });
      }

      // 3. Missing Idempotency on Critical Mutations
      const isCriticalMutation =
        /(?:charge|payment|checkout|transfer|order|deduct)\b/i.test(cleanCode) &&
        /(?:app\.post|router\.post|chargeCreditCard|createOrder|deduct)/i.test(cleanCode);

      const hasIdempotency = /idempotenc|x-idempotency-key|transactionId|clientNonce/i.test(cleanCode);

      if (isCriticalMutation && !hasIdempotency) {
        findings.push({
          personaType: 'CONFUSED_USER',
          attackVector: 'MISSING_IDEMPOTENCY',
          description: 'Critical payment/order endpoint lacks idempotency keys or deduplication, enabling duplicate financial charges on rapid user double-clicking.',
          suggestedTest: 'it("should reject or deduplicate rapid consecutive POST submissions with identical idempotency keys")',
          severity: 'HIGH',
          reproductionSteps: [
            'Send two identical POST /checkout requests within 50ms interval',
            'Observe whether two independent charges are recorded',
            'Verify only a single transaction completes successfully'
          ],
          affectedEntity: 'APIs'
        });
      }

      // 4. Boundary Violation (e.g. Negative values / Unbounded Numbers in financial context)
      const hasUnboundedNumber =
        /(?:balance\s*[-=]\s*amount|\bamount\b[\s\S]*?balance)/i.test(cleanCode) ||
        /(?:transfer|withdraw)\w*\s*\([^)]*amount/i.test(cleanCode) ||
        /(?:transfer|withdraw)\b[\s\S]*?\b(?:amount|balance|funds|quantity)\b/i.test(cleanCode);

      const hasPositiveGuard =
        /(?:amount\s*<=\s*0|amount\s*<\s*0|if\s*\([^)]*amount\s*>\s*0\)|typeof amount !== ['"]number['"])/i.test(cleanCode);

      if (hasUnboundedNumber && !hasPositiveGuard) {
        findings.push({
          personaType: 'CONFUSED_USER',
          attackVector: 'BOUNDARY_VIOLATION',
          description: 'Numeric balance/amount mutation lacks non-negative validation guard, allowing negative amounts to invert transfer logic or produce credit overdrafts.',
          suggestedTest: 'it("should reject negative or zero values for transfer/withdrawal amount")',
          severity: 'HIGH',
          reproductionSteps: [
            'Submit transfer request with negative amount: {"amount": -500}',
            'Verify system returns 400 validation error and denies transaction'
          ],
          affectedEntity: 'APIs'
        });
      }

      return findings;
    }
  };
}

