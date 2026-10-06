/**
 * BlastRadius-Zero Socratic Specification Generator
 * Decomposes informal engineering requirements into rigorous, testable contracts
 * with explicit invariants, edge cases, security controls, and RED verification plans.
 */

import { SocraticSpecResult } from './types.js';

export function generateSocraticSpec(
  requirement: string,
  targetComponents: string[] = [],
  depth: 'HIGH_LEVEL' | 'DETAILED' | 'EXHAUSTIVE' = 'DETAILED'
): SocraticSpecResult {
  const featureName = deriveFeatureName(requirement);
  const componentsList = targetComponents.length > 0 ? targetComponents.join(', ') : 'core runtime';

  const summary = `Formal Socratic engineering specification for "${requirement.trim()}". ` +
    `Defines strict behavioral contracts, invariants, security controls, and TDD verification criteria across [${componentsList}].`;

  // Core Invariants
  const invariants: string[] = [
    'State transitions must be atomic and deterministic; partial or corrupted intermediate states are strictly forbidden.',
    'All state-mutating operations must support idempotent execution or deduplication via unique invocation keys.',
    'Zero confidential data leaks: auth tokens, credentials, and PII must never be emitted into logs, traces, or unauthenticated responses.'
  ];

  if (targetComponents.some(c => /gateway|api|router|proxy/i.test(c))) {
    invariants.push('Requests exceeding configured rate, volume, or schema limits must be cleanly rejected with RFC 7807 problem details without degrading host processes.');
  }
  if (targetComponents.some(c => /redis|cache|db|storage/i.test(c))) {
    invariants.push('Persistence interactions must survive network latency spikes, partition failures, and disconnections via circuit-breaker protection and reconnect backoff.');
  }
  if (depth === 'EXHAUSTIVE') {
    invariants.push('All asynchronous streams and subprocesses must have bounded buffer limits and guaranteed termination timeouts to prevent memory exhaustion.');
    invariants.push('Strict backward compatibility: schema modifications must be additive and not break existing consumers.');
  }

  // Preconditions & Postconditions
  const preconditions: string[] = [
    'Caller identity, cryptographic signatures, and execution privileges must be verified before processing.',
    'Incoming request payloads must strictly validate against designated Zod / JSON schemas before domain execution.',
    'Dependent subsystem services (caches, datastores, upstream proxies) must report healthy status or have active fallback routines.'
  ];

  const postconditions: string[] = [
    'Target system state is updated, verified against invariants, and committed atomically.',
    'Immutable HMAC-SHA256 audit ledger entry is appended recording action metadata and execution status.',
    'All temporary memory allocations, file descriptors, and stream buffers are reclaimed without leaks.'
  ];

  // Explicit Edge Cases
  const edgeCases: SocraticSpecResult['edgeCases'] = [
    {
      scenario: 'Empty or Null Input Handling',
      input: 'null, undefined, empty string "", whitespace only "   ", or empty object {}',
      expectedOutcome: 'Immediate validation rejection with clear error details; zero unhandled TypeError or uncaught exceptions.'
    },
    {
      scenario: 'Concurrent Race Conditions Under Load',
      input: '50 simultaneous asynchronous executions targeting identical resource key within 5ms window',
      expectedOutcome: 'Deterministic atomic resolution using distributed locking or compare-and-swap; zero duplicate execution or state corruption.'
    },
    {
      scenario: 'Numeric Boundaries & Integer Overflows',
      input: 'Negative integers (-1), zero (0), float numbers (0.0001), and Number.MAX_SAFE_INTEGER',
      expectedOutcome: 'Enforce boundary validation; reject out-of-range inputs with HTTP 400 or domain validation exception.'
    },
    {
      scenario: 'Unicode, Script Injection & Malformed Characters',
      input: '<script>alert(1)</script>, SQL payloads, null bytes "\\0", RTL unicode overrides, and emoji strings 💥',
      expectedOutcome: 'Sanitized, escaped, or safely rejected; zero SQL injection, XSS, or control character interpretation.'
    },
    {
      scenario: 'Network Timeout & Downstream Service Outage',
      input: 'Downstream dependency latency exceeding 5000ms or immediate connection refused (ECONNREFUSED)',
      expectedOutcome: 'Fast failure via circuit breaker; returns controlled error response without hanging indefinitely or unhandled promise rejection.'
    }
  ];

  if (depth === 'EXHAUSTIVE') {
    edgeCases.push(
      {
        scenario: 'Large Payload Buffer Overflow (DDoS Prevention)',
        input: '10MB serialized payload exceeding maximum configured memory buffer size',
        expectedOutcome: 'Request aborted early at stream ingress with HTTP 413 Payload Too Large; memory footprint bounded.'
      },
      {
        scenario: 'Clock Skew & Expired Token Replay Attack',
        input: 'Request payload containing timestamp > 300 seconds skewed from host UTC clock or replayed nonce',
        expectedOutcome: 'Request rejected due to timestamp divergence; replay attempt recorded in security alert log.'
      }
    );
  }

  // Security & DLP Requirements
  const securityRequirements: string[] = [
    'Authentication & Scope Verification: Strict validation of caller identity, JWT signatures, and RBAC permissions.',
    'Input Sanitization & Injection Defense: Automatic schema sanitization preventing command injection, path traversal, and prototype pollution.',
    'Credential & Secret Protection: High-entropy secrets and API keys must never be logged or echoed in plaintext; apply DLP redaction mask.',
    'Resource Governance: Rate limiting and concurrency throttling to mitigate denial-of-service and noisy neighbor exploitation.'
  ];

  // Concrete Test Verification Plan (RED Tests)
  const testPlan: SocraticSpecResult['testPlan'] = [
    {
      testName: 'test_red_baseline_failure_before_implementation',
      description: 'Assert that calling the new feature before implementation code is written fails as expected (RED phase).',
      assertionHint: 'assert.rejects(async () => featureCall(validInput), /not implemented|cannot find/)'
    },
    {
      testName: 'test_empty_and_null_input_boundary_rejection',
      description: 'Verify that invalid, null, and empty payloads are rejected without system crashes.',
      assertionHint: 'assert.throws(() => featureCall(null), /validation error|required/)'
    },
    {
      testName: 'test_concurrent_execution_race_condition_guard',
      description: 'Simulate 50 parallel calls and verify that state changes remain consistent and atomic.',
      assertionHint: 'assert.strictEqual(results.filter(r => r.success).length, 1)'
    },
    {
      testName: 'test_security_sanitization_and_unauthorized_rejection',
      description: 'Verify that unauthenticated callers and malicious payloads are cleanly rejected.',
      assertionHint: 'assert.rejects(async () => featureCall({ maliciousPayload }), /unauthorized|forbidden/)'
    }
  ];

  if (depth === 'EXHAUSTIVE') {
    testPlan.push({
      testName: 'test_network_timeout_and_circuit_breaker_fallback',
      description: 'Simulate delayed dependency response and verify fallback circuit-breaker mechanism triggers.',
      assertionHint: 'assert.strictEqual(result.fallbackActivated, true)'
    });
  }

  // Generate Markdown Spec
  const markdownSpec = buildMarkdownSpec({
    featureName,
    requirement,
    summary,
    componentsList,
    depth,
    invariants,
    preconditions,
    postconditions,
    edgeCases,
    securityRequirements,
    testPlan
  });

  return {
    featureName,
    summary,
    invariants,
    preconditions,
    postconditions,
    edgeCases,
    securityRequirements,
    testPlan,
    markdownSpec
  };
}

function deriveFeatureName(requirement: string): string {
  const words = requirement
    .replace(/[^a-zA-Z0-9\s_-]/g, ' ')
    .trim()
    .split(/\s+/)
    .slice(0, 6);
  return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

interface MarkdownParams {
  featureName: string;
  requirement: string;
  summary: string;
  componentsList: string;
  depth: string;
  invariants: string[];
  preconditions: string[];
  postconditions: string[];
  edgeCases: SocraticSpecResult['edgeCases'];
  securityRequirements: string[];
  testPlan: SocraticSpecResult['testPlan'];
}

function buildMarkdownSpec(p: MarkdownParams): string {
  const lines: string[] = [];

  lines.push(`# Socratic Specification: ${p.featureName}`);
  lines.push(`**Target Requirement**: ${p.requirement.trim()}`);
  lines.push(`**Components**: ${p.componentsList} | **Depth**: ${p.depth}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(p.summary);
  lines.push('');
  lines.push('## User Intent & Core Invariants');
  lines.push('The following system invariants must be maintained without exception:');
  p.invariants.forEach((inv, i) => lines.push(`${i + 1}. **Invariant**: ${inv}`));
  lines.push('');
  lines.push('## Pre-conditions & Post-conditions');
  lines.push('### Pre-conditions');
  p.preconditions.forEach(pre => lines.push(`- ${pre}`));
  lines.push('### Post-conditions');
  p.postconditions.forEach(post => lines.push(`- ${post}`));
  lines.push('');
  lines.push('## Edge Cases');
  lines.push('| Scenario | Test Input | Expected Outcome |');
  lines.push('|---|---|---|');
  p.edgeCases.forEach(ec => {
    lines.push(`| **${ec.scenario}** | \`${ec.input}\` | ${ec.expectedOutcome} |`);
  });
  lines.push('');
  lines.push('## Security & DLP Assumptions');
  p.securityRequirements.forEach(sec => lines.push(`- 🔒 ${sec}`));
  lines.push('');
  lines.push('## Concrete Test Verification Plan (RED -> GREEN)');
  lines.push('All tests must be written and confirmed FAILING before any production code is touched:');
  p.testPlan.forEach((tp, i) => {
    lines.push(`### ${i + 1}. \`${tp.testName}\``);
    lines.push(`- **Description**: ${tp.description}`);
    lines.push(`- **Assertion Hint**: \`${tp.assertionHint}\``);
  });

  return lines.join('\n');
}
