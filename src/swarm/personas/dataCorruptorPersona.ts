import { AdversarialPersona, PersonaFinding } from '../types.js';

/**
 * Data Corruptor Persona:
 * Simulates null byte injection, Unicode normalization homoglyphs,
 * type confusion, NaN/Infinity propagation, and binary boundary overflows.
 */
export function createDataCorruptorPersona(id = 'corruptor-01'): AdversarialPersona {
  return {
    id,
    name: 'Data Corruptor Persona',
    type: 'DATA_CORRUPTOR',
    description: 'Adversarial agent injecting null bytes, Unicode homoglyphs, type confusion objects, and numeric singularities',
    focusArea: 'DATA_INTEGRITY',
    evaluate(diffOrCommand: string, _context?: Record<string, any>): PersonaFinding[] {
      const findings: PersonaFinding[] = [];
      const cleanCode = diffOrCommand.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // 1. Poison Null Byte / Path Injection
      const hasFsOrPathCall =
        /(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|open|stat)|path\.(?:join|resolve))\s*\([^)]*(?:req\.|params|filename|filePath)/i.test(cleanCode);
      const hasNullByteGuard =
        /(?:indexOf\(['"]\\0['"]\)|includes\(['"]\\0['"]\)|\.includes\(['"]%00['"]\)|nullByte)/i.test(cleanCode);

      if (hasFsOrPathCall && !hasNullByteGuard) {
        findings.push({
          personaType: 'DATA_CORRUPTOR',
          attackVector: 'NULL_BYTE_POISONING',
          description: 'Filesystem operation accepts untrusted path input without stripping poison null bytes (\\x00), allowing extension truncation or path filter bypass.',
          suggestedTest: 'it("should reject filenames or paths containing null byte characters (\\\\0)")',
          severity: 'HIGH',
          reproductionSteps: [
            'Send filename parameter with embedded null byte: "safe.txt\\x00.exe"',
            'Trigger file operation',
            'Verify server throws validation error and rejects file access'
          ],
          affectedEntity: 'Filesystem'
        });
      }

      // 2. Type Confusion / NoSQL Object Injection
      const hasDirectObjectQuery =
        /(?:find|findOne|where)\s*\(\s*\{\s*\w+\s*:\s*req\.(?:body|query)\.\w+\s*\}\s*\)/i.test(cleanCode) ||
        /(?:User|Account|Session)\.findOne\s*\([^)]*req\.(?:body|query)/i.test(cleanCode);
      const hasTypeCheck =
        /typeof\s+[^=!<]+===?\s*['"]string['"]|z\.(?:string|number)|typeof\s+[^=!<]+!==\s*['"]object['"]/i.test(cleanCode);

      if (hasDirectObjectQuery && !hasTypeCheck) {
        findings.push({
          personaType: 'DATA_CORRUPTOR',
          attackVector: 'TYPE_CONFUSION_INJECTION',
          description: 'Query criteria accepts unvalidated payload property directly. Passing an object like {"$gt": ""} instead of a primitive string bypasses equality checks.',
          suggestedTest: 'it("should strictly enforce primitive string type on query parameters to prevent NoSQL object injection")',
          severity: 'HIGH',
          reproductionSteps: [
            'Send payload with nested operator object: {"username": "admin", "password": {"$ne": null}}',
            'Verify schema validation rejects non-string types'
          ],
          affectedEntity: 'Database'
        });
      }

      // 3. Unchecked Numeric Parsing / NaN / Infinity Propagation
      const hasUncheckedNumberParse =
        /(?:parseInt|parseFloat|Number)\s*\(\s*(?:req\.|payload\.|input\.)[^)]*\)/i.test(cleanCode) &&
        !/Number\.isFinite|Number\.isNaN|Number\.isInteger|isNaN\(/i.test(cleanCode);

      if (hasUncheckedNumberParse) {
        findings.push({
          personaType: 'DATA_CORRUPTOR',
          attackVector: 'NUMERIC_SINGULARITY_NAN',
          description: 'Numeric parsing from request input lacks Number.isFinite() or Number.isNaN() check. Parsing "NaN" or "Infinity" produces arithmetic singularities that corrupt balances or state.',
          suggestedTest: 'it("should reject non-finite numeric inputs such as NaN and Infinity")',
          severity: 'MEDIUM',
          reproductionSteps: [
            'Send numeric input with value "NaN" or "Infinity"',
            'Observe calculation results',
            'Verify application returns 400 Bad Request rather than propagating NaN'
          ],
          affectedEntity: 'APIs'
        });
      }

      // 4. Unicode Normalization / Homoglyph Collision
      const hasStringComparison =
        /\.toLowerCase\(\)\s*===/i.test(cleanCode) &&
        /req\.(?:body|query|headers)/i.test(cleanCode);
      const hasNormalization = /\.normalize\s*\(/i.test(cleanCode);

      if (hasStringComparison && !hasNormalization) {
        findings.push({
          personaType: 'DATA_CORRUPTOR',
          attackVector: 'UNICODE_HOMOGLYPH_COLLISION',
          description: 'String comparison uses case conversion without Unicode normalization (.normalize("NFKC")), allowing homoglyph lookalike characters to collide or bypass identity checks.',
          suggestedTest: 'it("should normalize Unicode strings with NFKC before performing canonical identity comparisons")',
          severity: 'LOW',
          reproductionSteps: [
            'Register identity using Unicode homoglyph (e.g. Cyrillic "а" instead of Latin "a")',
            'Compare against standard canonical name',
            'Verify normalization treats lookalikes consistently'
          ],
          affectedEntity: 'Auth'
        });
      }

      return findings;
    }
  };
}
