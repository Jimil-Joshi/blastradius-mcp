/**
 * BlastRadius-Zero Automated Code Critique
 * Senior-dev static analysis and security heuristics for code diffs and source files.
 */

import { CodeCritiqueResult, CodeCritiqueFinding } from './types.js';

export function critiqueCode(
  diffOrCode: string,
  filePath?: string,
  strictSecurity: boolean = false
): CodeCritiqueResult {
  const findings: CodeCritiqueFinding[] = [];
  const lines = diffOrCode.split(/\r?\n/);
  const isTest = isTestFile(filePath, diffOrCode);

  // 1. Inspect Empty Catch Blocks
  inspectEmptyCatchBlocks(diffOrCode, filePath, findings);

  // 2. Inspect Dangerous Shell Sinks
  inspectDangerousShellSinks(lines, filePath, findings);

  // 3. Inspect Missing Test Assertions (in test code)
  if (isTest) {
    inspectMissingTestAssertions(diffOrCode, filePath, findings);
  }

  // 4. Inspect Unchecked External Inputs
  inspectUncheckedInputs(lines, filePath, findings);

  // 5. Inspect Unbounded Database Queries
  inspectUnboundedQueries(diffOrCode, filePath, findings);

  // Calculate score
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL':
        score -= 25;
        break;
      case 'HIGH':
        score -= 15;
        break;
      case 'MEDIUM':
        score -= 10;
        break;
      case 'LOW':
        score -= 5;
        break;
    }
  }
  score = Math.max(0, score);

  const hasCritical = findings.some(f => f.severity === 'CRITICAL');
  const passingThreshold = strictSecurity ? 80 : 70;
  const passed = score >= passingThreshold && !hasCritical;

  const analyzedFiles = [filePath || 'snippet'];
  const summary = `Analyzed ${analyzedFiles.length} file(s). Found ${findings.length} finding(s). ` +
    `Quality score: ${score}/100 (${passed ? 'PASSED' : 'FAILED'}).`;

  return {
    score,
    passed,
    findingsCount: findings.length,
    findings,
    summary,
    analyzedFiles
  };
}

function isTestFile(filePath?: string, code?: string): boolean {
  if (filePath) {
    const normalized = filePath.replace(/\\/g, '/').toLowerCase();
    if (
      /(^|\/)(test|tests|spec|specs|__tests__|__specs__)\//.test(normalized) ||
      /(\.|\b|_|-)(test|spec)\.[a-z0-9]+$/i.test(normalized) ||
      /(^|\/)(test|spec)[_\.-][a-z0-9_-]+\.[a-z0-9]+$/i.test(normalized)
    ) {
      return true;
    }
  }
  if (code && (/\b(?:test|it|describe)\s*\(/i.test(code))) {
    return true;
  }
  return false;
}

function inspectEmptyCatchBlocks(code: string, filePath?: string, findings?: CodeCritiqueFinding[]): void {
  if (!findings) return;

  // Match catch blocks across single or multiple lines
  const catchRegex = /catch\s*(?:\([^)]*\))?\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;

  while ((match = catchRegex.exec(code)) !== null) {
    const catchBody = match[1];
    // Strip comments and whitespace
    const stripped = catchBody
      .replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '')
      .trim();

    if (stripped.length === 0) {
      const matchIndex = match.index;
      const precedingCode = code.slice(0, matchIndex);
      const lineNumber = precedingCode.split(/\r?\n/).length;
      const lineContent = code.split(/\r?\n/)[lineNumber - 1] || 'catch (...) {}';

      findings.push({
        ruleId: 'NO_EMPTY_CATCH',
        category: 'ERROR_HANDLING',
        severity: 'HIGH',
        filePath,
        lineNumber,
        lineContent: lineContent.trim(),
        message: 'Empty catch block detected. Swallowing exceptions hides bugs and critical failures.',
        suggestion: 'Log the error with context or rethrow: console.error(err) or throw err;'
      });
    }
  }
}

function inspectDangerousShellSinks(lines: string[], filePath?: string, findings?: CodeCritiqueFinding[]): void {
  if (!findings) return;

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    // Ignore comments
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    const sinks: Array<{ name: string; regex: RegExp }> = [
      { name: 'eval', regex: /\beval\s*\(/ },
      { name: 'Function constructor', regex: /\bFunction\s*\(/ },
      { name: 'child_process', regex: /['"]child_process['"]/ },
      { name: 'exec', regex: /(?<!\.)\bexec\s*\(|(?:child_process|cp)\.exec\s*\(/ },
      { name: 'spawn', regex: /(?<!\.)\bspawn\s*\(|(?:child_process|cp)\.spawn\s*\(/ }
    ];

    for (const sink of sinks) {
      if (sink.regex.test(trimmed)) {
        findings.push({
          ruleId: 'DANGEROUS_SHELL_SINK',
          category: 'SECURITY',
          severity: 'CRITICAL',
          filePath,
          lineNumber: index + 1,
          lineContent: trimmed,
          message: `Dangerous execution sink (${sink.name}) detected. Arbitrary command execution vulnerability.`,
          suggestion: 'Replace raw execution sink with parameterized, safe APIs or sandboxed execution.'
        });
      }
    }
  });
}

function inspectMissingTestAssertions(code: string, filePath?: string, findings?: CodeCritiqueFinding[]): void {
  if (!findings) return;

  // Regex to match test('...', () => { ... }) or it('...', () => { ... })
  const testRegex = /(?:test|it)\s*\(\s*(['"`][^'"`]+['"`])\s*,\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*\{([\s\S]*?)\n\s*\}\s*\)/g;
  let match: RegExpExecArray | null;

  while ((match = testRegex.exec(code)) !== null) {
    const testTitle = match[1];
    const testBody = match[2];

    const hasAssertion = /\b(?:assert|expect|should|verify)\b/i.test(testBody);
    if (!hasAssertion) {
      const matchIndex = match.index;
      const precedingCode = code.slice(0, matchIndex);
      const lineNumber = precedingCode.split(/\r?\n/).length;
      const lineContent = code.split(/\r?\n/)[lineNumber - 1] || `test(${testTitle})`;

      findings.push({
        ruleId: 'MISSING_TEST_ASSERTION',
        category: 'QUALITY',
        severity: 'MEDIUM',
        filePath,
        lineNumber,
        lineContent: lineContent.trim(),
        message: `Test block ${testTitle} lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.`,
        suggestion: 'Add explicit assertions: assert.strictEqual(...) or expect(...).toBe(...)'
      });
    }
  }
}

function inspectUncheckedInputs(lines: string[], filePath?: string, findings?: CodeCritiqueFinding[]): void {
  if (!findings) return;

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    // Direct access to req.body.foo without optional chaining or schema check
    const uncheckedReqBody = /\breq\.body\.[a-zA-Z0-9_]+/.test(trimmed) && !trimmed.includes('?.');
    const uncheckedReqQuery = /\breq\.(query|params)\.[a-zA-Z0-9_]+/.test(trimmed) && !trimmed.includes('?.');

    if (uncheckedReqBody || uncheckedReqQuery) {
      findings.push({
        ruleId: 'UNCHECKED_INPUT',
        category: 'SECURITY',
        severity: 'MEDIUM',
        filePath,
        lineNumber: index + 1,
        lineContent: trimmed,
        message: 'Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.',
        suggestion: 'Validate incoming payload using Zod schemas or safe optional chaining (?.) and null checks.'
      });
    }
  });
}

function inspectUnboundedQueries(code: string, filePath?: string, findings?: CodeCritiqueFinding[]): void {
  if (!findings) return;

  // Match SQL SELECT ... FROM queries across single or multiple lines in strings or template literals
  const queryRegex = /(?:['"`])\s*(SELECT\b[\s\S]*?\bFROM\b[\s\S]*?)(?:['"`]|;)/gi;
  let match: RegExpExecArray | null;

  while ((match = queryRegex.exec(code)) !== null) {
    const queryBody = match[1];
    const hasLimit = /\b(?:LIMIT|take|TOP|FETCH FIRST)\b/i.test(queryBody);

    if (!hasLimit) {
      const matchIndex = match.index;
      const precedingCode = code.slice(0, matchIndex);
      const lineNumber = precedingCode.split(/\r?\n/).length;
      const lines = code.split(/\r?\n/);
      const lineContent = lines[lineNumber - 1] || queryBody.slice(0, 60);

      findings.push({
        ruleId: 'UNBOUNDED_DB_QUERY',
        category: 'PERFORMANCE',
        severity: 'MEDIUM',
        filePath,
        lineNumber,
        lineContent: lineContent.trim(),
        message: 'Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.',
        suggestion: 'Add a LIMIT clause or paginated take constraint to protect datastore and memory buffers.'
      });
    }
  }

  // Also check single-line non-quoted queries if not already flagged
  const lines = code.split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
    if (/\bSELECT\b[\s\S]*?\bFROM\b/i.test(trimmed)) {
      const alreadyFlagged = findings.some(
        f => f.lineNumber === index + 1 && f.ruleId === 'UNBOUNDED_DB_QUERY'
      );
      if (!alreadyFlagged) {
        const hasLimit = /\b(?:LIMIT|take|TOP|FETCH FIRST)\b/i.test(trimmed);
        if (!hasLimit) {
          findings.push({
            ruleId: 'UNBOUNDED_DB_QUERY',
            category: 'PERFORMANCE',
            severity: 'MEDIUM',
            filePath,
            lineNumber: index + 1,
            lineContent: trimmed,
            message: 'Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.',
            suggestion: 'Add a LIMIT clause or paginated take constraint to protect datastore and memory buffers.'
          });
        }
      }
    }
  });
}
