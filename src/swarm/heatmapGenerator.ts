import { HeatmapMatrix, PersonaFinding } from './types.js';

const STANDARD_COMPONENTS = ['Auth', 'Database', 'Storage', 'Network', 'Filesystem', 'APIs'] as const;
type StandardComponent = typeof STANDARD_COMPONENTS[number];

/**
 * Generate a comprehensive Blast Radius Heatmap Matrix evaluating
 * components, user classes, data sensitivity, and containment feasibility.
 */
export function generateHeatmap(
  targetDiffOrCommand: string,
  findings: PersonaFinding[],
  riskScore: number
): HeatmapMatrix {
  const componentMap = new Map<StandardComponent, { risk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; score: number; description: string }>();

  // Initialize all standard components to SAFE
  for (const comp of STANDARD_COMPONENTS) {
    componentMap.set(comp, {
      risk: 'SAFE',
      score: 0,
      description: 'No adversarial impact detected'
    });
  }

  // Assess findings impact per component
  for (const finding of findings) {
    let targetComponent: StandardComponent = 'APIs';

    if (
      finding.affectedEntity === 'Database' ||
      finding.attackVector === 'SQL_INJECTION' ||
      finding.attackVector === 'TOCTOU_RACE_CONDITION' ||
      finding.attackVector === 'TYPE_CONFUSION_INJECTION'
    ) {
      targetComponent = 'Database';
    } else if (
      finding.affectedEntity === 'Auth' ||
      finding.attackVector === 'AUTH_BYPASS' ||
      finding.attackVector === 'IDOR' ||
      finding.attackVector === 'PRIVILEGE_ESCALATION' ||
      finding.attackVector === 'TOKEN_TAMPERING' ||
      finding.attackVector === 'CONCURRENT_TOKEN_REFRESH' ||
      finding.attackVector === 'UNICODE_HOMOGLYPH_COLLISION'
    ) {
      targetComponent = 'Auth';
    } else if (
      finding.affectedEntity === 'Filesystem' ||
      finding.attackVector === 'SHELL_INJECTION' ||
      finding.attackVector === 'COMMAND_INJECTION' ||
      finding.attackVector === 'NULL_BYTE_POISONING'
    ) {
      targetComponent = 'Filesystem';
    } else if (finding.affectedEntity === 'Network' || finding.attackVector === 'SOCKET_TIMEOUT_HANG') {
      targetComponent = 'Network';
    } else if (finding.affectedEntity === 'Storage' || finding.attackVector === 'CACHE_DESYNCHRONIZATION') {
      targetComponent = 'Storage';
    } else if (finding.affectedEntity === 'APIs') {
      targetComponent = 'APIs';
    }

    const findingScore =
      finding.severity === 'CRITICAL' ? 85 :
      finding.severity === 'HIGH' ? 68 :
      finding.severity === 'MEDIUM' ? 45 : 20;

    const findingRisk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' =
      findingScore >= 75 ? 'CRITICAL' :
      findingScore >= 60 ? 'HIGH' :
      findingScore >= 35 ? 'MEDIUM' : 'LOW';

    const current = componentMap.get(targetComponent)!;
    if (findingScore > current.score) {
      componentMap.set(targetComponent, {
        risk: findingRisk,
        score: findingScore,
        description: finding.description.slice(0, 75)
      });
    }
  }

  // Also check diff contents for mild baseline involvement if score is still 0
  const diffLower = targetDiffOrCommand.toLowerCase();
  if (componentMap.get('Database')!.score === 0 && /\b(select|insert|update|delete|sql|database|db\.)\b/.test(diffLower)) {
    componentMap.set('Database', { risk: 'LOW', score: 20, description: 'Direct database access referenced in diff' });
  }
  if (componentMap.get('Auth')!.score === 0 && /\b(jwt|token|auth|password|session|oauth)\b/.test(diffLower)) {
    componentMap.set('Auth', { risk: 'LOW', score: 20, description: 'Authentication components referenced in diff' });
  }
  if (componentMap.get('Network')!.score === 0 && /\b(fetch|http|axios|request|url)\b/.test(diffLower)) {
    componentMap.set('Network', { risk: 'LOW', score: 15, description: 'Network I/O operations present in diff' });
  }
  if (componentMap.get('Filesystem')!.score === 0 && /\b(fs\.|exec|spawn|file|path)\b/.test(diffLower)) {
    componentMap.set('Filesystem', { risk: 'LOW', score: 15, description: 'Filesystem / process operations present in diff' });
  }

  const cells = STANDARD_COMPONENTS.map(comp => ({
    component: comp,
    ...componentMap.get(comp)!
  }));

  // User Classes exposure
  const hasAuthRisk = componentMap.get('Auth')!.score >= 60;
  const hasDbRisk = componentMap.get('Database')!.score >= 60;
  const hasApiRisk = componentMap.get('APIs')!.score >= 40;

  const userClasses: HeatmapMatrix['userClasses'] = [
    {
      userClass: 'Admin',
      exposure: hasAuthRisk ? 'CRITICAL' : (riskScore >= 40 ? 'ELEVATED' : 'SAFE'),
      detail: hasAuthRisk
        ? 'Privilege boundary escalation or auth bypass permits unauthorized admin actions'
        : 'Admin perimeter secure'
    },
    {
      userClass: 'Customer',
      exposure: hasDbRisk || hasAuthRisk ? 'CRITICAL' : (hasApiRisk ? 'ELEVATED' : 'SAFE'),
      detail: hasDbRisk
        ? 'Tenant isolation compromised via data query vulnerability'
        : (hasApiRisk ? 'Potential validation crash or state desync on customer actions' : 'Customer records isolated')
    },
    {
      userClass: 'Guest',
      exposure: hasAuthRisk ? 'ELEVATED' : 'SAFE',
      detail: hasAuthRisk ? 'Unauthenticated access path available' : 'Guest session boundaries enforced'
    },
    {
      userClass: 'Public',
      exposure: riskScore >= 70 ? 'CRITICAL' : (riskScore >= 30 ? 'ELEVATED' : 'SAFE'),
      detail: riskScore >= 70
        ? 'Public attack surface vulnerable to exploit'
        : (riskScore >= 30 ? 'Potential public API degradation or malformed input crash' : 'No public blast radius')
    }
  ];

  // Data Sensitivity exposure
  const hasTokenRisk = findings.some(f => f.attackVector === 'TOKEN_TAMPERING' || f.attackVector === 'AUTH_BYPASS');
  const hasDataLeakRisk = findings.some(f => f.attackVector === 'SQL_INJECTION' || f.attackVector === 'IDOR');

  const dataSensitivity: HeatmapMatrix['dataSensitivity'] = [
    {
      category: 'Secrets',
      exposure: hasTokenRisk ? 'CRITICAL' : (riskScore >= 50 ? 'ELEVATED' : 'CONTAINED'),
      detail: hasTokenRisk ? 'API tokens, cryptographic keys or session secrets exposed' : 'Secrets protected'
    },
    {
      category: 'PII',
      exposure: hasDataLeakRisk ? 'CRITICAL' : (riskScore >= 40 ? 'ELEVATED' : 'CONTAINED'),
      detail: hasDataLeakRisk ? 'Personally identifiable customer data accessible without authorization' : 'PII boundaries intact'
    },
    {
      category: 'Internal',
      exposure: riskScore >= 40 ? 'ELEVATED' : 'CONTAINED',
      detail: riskScore >= 40 ? 'Internal system traces, schemas, or network hosts discoverable' : 'Internal topology shielded'
    },
    {
      category: 'Public',
      exposure: 'CONTAINED',
      detail: 'Public content safe'
    }
  ];

  // Containment Feasibility
  const containmentFeasibility: HeatmapMatrix['containmentFeasibility'] =
    riskScore >= 70
      ? {
          level: 'LOW',
          rollbackEase: 'MANUAL_DB_REPAIR_OR_SECRET_ROTATION_REQUIRED',
          compensationActions: [
            'Immediately revoke and rotate active tokens',
            'Enforce parameterized database queries and enable row-level security',
            'Remove authentication bypass switches'
          ]
        }
      : riskScore >= 30
      ? {
          level: 'MEDIUM',
          rollbackEase: 'REVERSIBLE_WITH_SERVICE_RESTART',
          compensationActions: [
            'Introduce input validation schema with zod/joi',
            'Configure explicit network socket timeouts (e.g. AbortSignal.timeout(5000))',
            'Wrap state mutations in transactional locks'
          ]
        }
      : {
          level: 'HIGH',
          rollbackEase: 'INSTANT_ATOMIC_ROLLBACK',
          compensationActions: [
            'Standard automated deployment and blue/green rollout safe'
          ]
        };

  const matrixBase = {
    dimensions: {
      components: [...STANDARD_COMPONENTS],
      riskLevels: ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    cells,
    overallScore: riskScore,
    userClasses,
    dataSensitivity,
    containmentFeasibility
  };

  const asciiTable = renderHeatmapAscii(matrixBase as HeatmapMatrix);
  const markdownTable = renderHeatmapMarkdown(matrixBase as HeatmapMatrix);

  return {
    ...matrixBase,
    asciiTable,
    markdownTable
  };
}

/**
 * Render visual ASCII grid representation of the Blast Radius Heatmap.
 */
export function renderHeatmapAscii(matrix: HeatmapMatrix): string {
  const verdict = matrix.overallScore >= 70 ? 'BLOCK' : matrix.overallScore >= 30 ? 'WARN' : 'SAFE';
  const lines: string[] = [];

  lines.push('+-----------------------------------------------------------------------------------------+');
  lines.push('|                                BLASTRADIUS BLAST HEATMAP                                |');
  lines.push('+-------------------+------------+-------+------------------------------------------------+');
  lines.push('| COMPONENT         | RISK LEVEL | SCORE | IMPACT SUMMARY                                 |');
  lines.push('+-------------------+------------+-------+------------------------------------------------+');

  for (const cell of matrix.cells) {
    const comp = cell.component.padEnd(17, ' ');
    const risk = cell.risk.padEnd(10, ' ');
    const score = String(cell.score).padStart(5, ' ');
    const desc = (cell.description.length > 46 ? cell.description.slice(0, 43) + '...' : cell.description).padEnd(46, ' ');
    lines.push(`| ${comp} | ${risk} | ${score} | ${desc} |`);
  }

  lines.push('+-------------------+------------+-------+------------------------------------------------+');
  const overallText = `OVERALL PR RISK: ${matrix.overallScore} / 100   |   VERDICT: ${verdict}`.padEnd(87, ' ');
  lines.push(`| ${overallText} |`);
  lines.push('+-----------------------------------------------------------------------------------------+');

  if (matrix.userClasses && matrix.userClasses.length > 0) {
    lines.push('| USER CLASS EXPOSURE                                                                     |');
    for (const uc of matrix.userClasses) {
      const line = `  • ${uc.userClass}: [${uc.exposure}] - ${uc.detail}`.slice(0, 87).padEnd(87, ' ');
      lines.push(`| ${line} |`);
    }
    lines.push('+-----------------------------------------------------------------------------------------+');
  }

  if (matrix.dataSensitivity && matrix.dataSensitivity.length > 0) {
    lines.push('| DATA SENSITIVITY                                                                        |');
    for (const ds of matrix.dataSensitivity) {
      const line = `  • ${ds.category}: [${ds.exposure}] - ${ds.detail}`.slice(0, 87).padEnd(87, ' ');
      lines.push(`| ${line} |`);
    }
    lines.push('+-----------------------------------------------------------------------------------------+');
  }

  return lines.join('\n');
}

/**
 * Render rich GitHub-flavored Markdown representation with badges.
 */
export function renderHeatmapMarkdown(matrix: HeatmapMatrix): string {
  const verdict = matrix.overallScore >= 70 ? 'BLOCK' : matrix.overallScore >= 30 ? 'WARN' : 'SAFE';
  const md: string[] = [];

  md.push(`### BlastRadius Blast Heatmap (Overall Risk: ${matrix.overallScore}/100 — Verdict: \`${verdict}\`)\n`);
  md.push('| Component | Risk Level | Score | Impact Summary |');
  md.push('|:---|:---:|:---:|:---|');

  for (const cell of matrix.cells) {
    const badge =
      cell.risk === 'CRITICAL' ? '`[CRITICAL]`' :
      cell.risk === 'HIGH' ? '`[ELEVATED]`' :
      cell.risk === 'MEDIUM' ? '`[MEDIUM]`' :
      cell.risk === 'LOW' ? '`[LOW]`' : '`[CONTAINED]`';

    md.push(`| **${cell.component}** | ${badge} | ${cell.score} | ${cell.description} |`);
  }

  if (matrix.userClasses && matrix.userClasses.length > 0) {
    md.push('\n#### User Class Exposure');
    md.push('| User Class | Exposure | Detail |');
    md.push('|:---|:---:|:---|');
    for (const uc of matrix.userClasses) {
      const badge = uc.exposure === 'CRITICAL' ? '`[CRITICAL]`' : uc.exposure === 'ELEVATED' ? '`[ELEVATED]`' : '`[SAFE]`';
      md.push(`| ${uc.userClass} | ${badge} | ${uc.detail} |`);
    }
  }

  if (matrix.dataSensitivity && matrix.dataSensitivity.length > 0) {
    md.push('\n#### Data Sensitivity Exposure');
    md.push('| Category | Exposure | Detail |');
    md.push('|:---|:---:|:---|');
    for (const ds of matrix.dataSensitivity) {
      const badge = ds.exposure === 'CRITICAL' ? '`[CRITICAL]`' : ds.exposure === 'ELEVATED' ? '`[ELEVATED]`' : '`[CONTAINED]`';
      md.push(`| ${ds.category} | ${badge} | ${ds.detail} |`);
    }
  }

  if (matrix.containmentFeasibility) {
    md.push('\n#### Containment Feasibility');
    md.push(`- **Feasibility Level:** \`${matrix.containmentFeasibility.level}\``);
    md.push(`- **Rollback Ease:** \`${matrix.containmentFeasibility.rollbackEase}\``);
    md.push('- **Recommended Compensations:**');
    for (const act of matrix.containmentFeasibility.compensationActions) {
      md.push(`  - ${act}`);
    }
  }

  return md.join('\n');
}

