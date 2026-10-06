import { AdversarialPersona, PersonaFinding } from '../types.js';

/**
 * Security Hacker Persona:
 * Attacks auth bypass, IDOR, SQL/shell injection, privilege escalation, and token tampering.
 */
export function createHackerPersona(id = 'hacker-01'): AdversarialPersona {
  return {
    id,
    name: 'Security Hacker Persona',
    type: 'HACKER',
    description: 'Adversarial attacker stress-testing authentication, authorization, injection, and token boundaries',
    focusArea: 'SECURITY',
    evaluate(diffOrCommand: string, _context?: Record<string, any>): PersonaFinding[] {
      const findings: PersonaFinding[] = [];
      const cleanCode = diffOrCommand.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // 1. SQL Injection Detection
      const hasSqlConcat =
        /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\${/i.test(cleanCode) ||
        /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\+[\s\S]*?['"`]/i.test(cleanCode) ||
        /(?:query|execute|raw)\s*\(\s*(['"`][^'"`]*?\+[\s\S]*?|`[^`]*?\${)/i.test(cleanCode);

      if (hasSqlConcat) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'SQL_INJECTION',
          description: 'Interpolation or concatenation of unescaped variables directly into SQL queries allows arbitrary statement execution or data exfiltration.',
          suggestedTest: 'it("should reject malicious SQL injection payload and enforce parameterized queries")',
          severity: 'CRITICAL',
          reproductionSteps: [
            'Craft payload with SQL termination sequence: "\' OR \'1\'=\'1"',
            'Submit payload into target parameter/argument',
            'Verify query execution escapes payload and does not leak unauthorized records'
          ],
          affectedEntity: 'Database'
        });
      }

      // 2. Auth Bypass Detection
      const hasAuthBypass =
        /x-bypass-auth/i.test(cleanCode) ||
        /\bskipAuth\b/i.test(cleanCode) ||
        /\bauth\s*:\s*false\b/i.test(cleanCode) ||
        /\b(?:bypassAuth|disableAuth|skip_auth)\b/i.test(cleanCode) ||
        /if\s*\([^)]*(?:bypass|skipAuth|noAuth|admin-override)[^)]*\)\s*(?:return|next)/i.test(cleanCode) ||
        /req\.headers\['x-admin-override'\]/i.test(cleanCode);

      if (hasAuthBypass) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'AUTH_BYPASS',
          description: 'Hardcoded auth bypass flag or unsecured header allows unauthenticated callers to skip security middleware.',
          suggestedTest: 'it("should reject unauthenticated requests even if bypass header or parameter is present")',
          severity: 'CRITICAL',
          reproductionSteps: [
            'Send HTTP request without authentication token',
            'Include header "x-bypass-auth: true" or query param "?skipAuth=1"',
            'Verify endpoint returns 401/403 and never bypasses authentication'
          ],
          affectedEntity: 'Auth'
        });
      }

      // 3. IDOR (Insecure Direct Object Reference) Detection
      const hasIdor =
        /(?:findById|findOne|find)\s*\(\s*req\.params\.\w+\s*\)/i.test(cleanCode) ||
        /\/api\/(?:documents|accounts|orders|users|profiles)\/:(\w+)[\s\S]*?(?:res\.json|return)/i.test(cleanCode);

      const hasTenantCheck = /tenant_id|tenantId|req\.user\.id|userId/i.test(cleanCode);

      if (hasIdor && !hasTenantCheck) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'IDOR',
          description: 'Direct resource lookup by URL parameter without verifying ownership or tenancy allows unauthorized access to peer records.',
          suggestedTest: 'it("should verify tenant/user ownership before returning requested object")',
          severity: 'HIGH',
          reproductionSteps: [
            'Authenticate as User A',
            'Request resource owned by User B by altering resource ID in path',
            'Verify system returns 403 Forbidden'
          ],
          affectedEntity: 'Auth'
        });
      }

      // 4. Shell / Command Injection Detection
      const hasShellInjection =
        /(?:child_process|exec|spawn)\s*\(|exec\s*\(\s*`[^`]*\${/i.test(cleanCode) ||
        /exec\s*\(\s*['"`][^'"`]*?\+/i.test(cleanCode) ||
        /\beval\s*\(/i.test(cleanCode);

      if (hasShellInjection) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'SHELL_INJECTION',
          description: 'Unsanitized string interpolation into shell execution command allows arbitrary host command execution.',
          suggestedTest: 'it("should prevent shell command injection through input arguments")',
          severity: 'CRITICAL',
          reproductionSteps: [
            'Inject command separator payload: "; rm -rf /tmp; #"',
            'Execute target function with injected argument',
            'Verify shell treats input as literal argument or rejects command'
          ],
          affectedEntity: 'Filesystem'
        });
      }

      // 5. Privilege Escalation Detection
      const hasPrivEscalation =
        /\b(?:role|isAdmin|permissions)\s*:\s*req\.body/i.test(cleanCode) ||
        /\{\s*\.\.\.req\.body\s*\}[\s\S]*?(?:User\.update|db\.users\.update|update)/i.test(cleanCode) ||
        /x-admin-override/i.test(cleanCode);

      if (hasPrivEscalation) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'PRIVILEGE_ESCALATION',
          description: 'Mass-assignment or unverified role update allows standard users to elevate privileges to administrator.',
          suggestedTest: 'it("should restrict role assignment to verified administrative contexts")',
          severity: 'HIGH',
          reproductionSteps: [
            'Submit profile update payload with {"role": "admin"} or {"isAdmin": true}',
            'Verify role field is ignored or rejected by validation schema'
          ],
          affectedEntity: 'Auth'
        });
      }

      // 6. Token Tampering / Weak Secret Detection
      const hasTokenTampering =
        /jwt\.verify\s*\([^,]+,\s*['"`](?:secret|default|password|123456)['"`]/i.test(cleanCode) ||
        /ignoreExpiration\s*:\s*true/i.test(cleanCode) ||
        /algorithms\s*:\s*\[['"`]none['"`]\]/i.test(cleanCode);

      if (hasTokenTampering) {
        findings.push({
          personaType: 'HACKER',
          attackVector: 'TOKEN_TAMPERING',
          description: 'Insecure JWT configuration: weak hardcoded secret or disabled expiration/signature verification.',
          suggestedTest: 'it("should reject forged tokens, enforce asymmetric keys, and validate expiration")',
          severity: 'HIGH',
          reproductionSteps: [
            'Sign token with algorithm "none" or default secret',
            'Provide expired token to endpoint',
            'Verify token validation strictly fails'
          ],
          affectedEntity: 'Auth'
        });
      }

      return findings;
    }
  };
}

