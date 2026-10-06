import { ActionCategory, BlastRadiusReport, SeverityLevel } from '../types.js';
import { DANGEROUS_RULES } from './rules.js';
import { ShellResolver, ResolvedCommand } from './shellResolver.js';

/**
   * Field names that carry prose rather than a command. Anything matching this
   * is never resolved as a command line, whatever it contains: the words in a
   * description are not an invocation.
 */
const NON_COMMAND_FIELD = /^(description|message|content|body|text|title|comment|notes?|reason|rationale|summary|instruction|instructions|prompt|document|readme|changelog|docs?|path|file|filename|filepath|dir|directory|target|url|uri|host|endpoint|image|image_url|branch|username|user|email|id|name|label|type|version|query|sql|statement|input|output|result|response|data|payload|body_text|summary_text)$/i;

/**
   * Keeps a resolved command short enough to sit in a reason line.
 */
function truncateForReport(value: string, limit: number = 200): string {
  return value.length <= limit ? value : `${value.slice(0, limit)}…`;
}

export class BlastRadiusEngine {
  /**
   * The last resolution result, kept so a caller inspecting a report can see
   * which form of the command was actually matched against.
   */
  public static lastResolution?: ResolvedCommand;

  /**
   * Automatically detect the category of an action if not explicitly provided.
   */
  public static inferCategory(content: string): ActionCategory {
    const trimmed = content.trim();
    if (/^(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE)\b/i.test(trimmed)) {
      return ActionCategory.SQL;
    }
    if (/\b(aws|gcloud|az|kubectl|terraform|helm)\b/i.test(trimmed)) {
      return ActionCategory.CLOUD;
    }
    if (/\b(rm|cp|mv|chmod|chown|touch|mkdir|cat|ls|pwd|grep|awk|sed|curl|wget|npm|pip|git|powershell|bash|sh)\b/i.test(trimmed)) {
      return ActionCategory.SHELL;
    }
    if (/\b(open|read|write|unlink|mkdir|rmdir|copyFile|writeFile)\b/i.test(trimmed)) {
      return ActionCategory.FILESYSTEM;
    }
    if (/\b(https?:\/\/|connect|ping|traceroute|nmap|netstat|ssh|scp)\b/i.test(trimmed)) {
      return ActionCategory.NETWORK;
    }
    return ActionCategory.GENERIC;
  }

  /**
   * Evaluates blast radius, danger score, and generates a simulation report.
   */
  public static evaluate(
    commandOrQuery: string,
    explicitCategory?: ActionCategory,
    context?: Record<string, any>
  ): BlastRadiusReport {
    const normalizedInput = commandOrQuery.trim();

    // `enforce_policy` hands this engine `JSON.stringify(params)`, so the real
    // input shape is a serialised object whose fields *are* the command line:
    // `{command:'rm', args:['-rf','/']}`. Resolving that string as shell text
    // tokenises `{command:` as a command word and `rm` as an argument, so the
    // deletion never reaches the rules. Each string leaf is resolved on its own
    // instead and the highest score wins.
    const structured = this.evaluateStructuredParams(normalizedInput, context);
    if (structured) return structured;

    const category = explicitCategory || this.inferCategory(normalizedInput);

    // Resolve the command the way the shell will, then match rules against what
    // it will actually run rather than what was submitted. A regex over the raw
    // string is the design GuardFall measured as bypassable; matching the
    // resolved form is what closes that gap.
    const resolution = ShellResolver.resolve(normalizedInput);
    this.lastResolution = resolution;

    let maxScore = 0;
    const reasons: string[] = [];
    const mitigations = new Set<string>();
    const affectedEntities = new Set<string>();
    let isDestructive = false;
    let isIrreversible = false;

    // Rules run against the resolved command first, because that is what the OS
    // receives. Falling back to the raw text keeps a SQL statement or a partially
    // resolved expression matchable when it is not shell-shaped at all.
    const candidates = [resolution.resolved, normalizedInput];

    // 1. Check against predefined signature rules
    for (const rule of DANGEROUS_RULES) {
      if (candidates.some((candidate) => rule.pattern.test(candidate))) {
        if (rule.dangerScore > maxScore) {
          maxScore = rule.dangerScore;
        }
        reasons.push(rule.reason);
        if (rule.destructive) isDestructive = true;
        if (rule.irreversible) isIrreversible = true;
        rule.mitigations.forEach((m) => mitigations.add(m));
      }
    }

    // 2. Structural facts the regex layer cannot express: a recursive delete
    // aimed through an unknown variable, or content piped into an interpreter.
    const structural = this.evaluateStructuralTraits(resolution);
    if (structural.score > maxScore) maxScore = structural.score;
    for (const reason of structural.reasons) reasons.push(reason);
    if (structural.destructive) isDestructive = true;
    if (structural.irreversible) isIrreversible = true;
    structural.mitigations.forEach((m) => mitigations.add(m));

    // 3. Extract potential affected targets (files, tables, cloud targets)
    this.extractAffectedTargets(resolution.resolved || normalizedInput, category, affectedEntities);
    for (const p of resolution.paths) affectedEntities.add(`path:${p}`);
    for (const r of resolution.cloudResources) affectedEntities.add(`cloud_resource:${r}`);

    // 4. Environmental escalation (e.g., prod context increases risk)
    const env = (context?.environment || context?.env || '').toString().toLowerCase();
    const isProduction = ['prod', 'production', 'live', 'main'].includes(env);

    if (isProduction && maxScore > 20) {
      maxScore = Math.min(100, maxScore + 20);
      reasons.push(`Target environment is marked as PRODUCTION (${env}), escalating blast radius.`);
      mitigations.add('Require multi-factor authorization and shadow dry-run prior to production execution.');
    }

    // 5. If safe with no matches
    if (maxScore === 0) {
      maxScore = 5;
      reasons.push('Standard read-only or low-impact routine action.');
      mitigations.add('Proceed under standard monitoring.');
    }

    // 6. Determine severity level from score
    let severity: SeverityLevel;
    if (maxScore >= 90) {
      severity = SeverityLevel.CRITICAL;
    } else if (maxScore >= 70) {
      severity = SeverityLevel.HIGH;
    } else if (maxScore >= 40) {
      severity = SeverityLevel.MEDIUM;
    } else if (maxScore >= 15) {
      severity = SeverityLevel.LOW;
    } else {
      severity = SeverityLevel.SAFE;
    }

    // 7. Feasibility of rollback
    const rollbackFeasible = !isIrreversible && maxScore < 90;

    // 8. Dry-run simulation data
    const simulatedOutput = isDestructive
      ? `[DRY-RUN SIMULATION]: Destructive action simulated. Affected entities: ${Array.from(affectedEntities).join(', ') || 'Global/Broad'}. Execution would permanently alter persistent state.`
      : `[DRY-RUN SIMULATION]: Safe/Read operation verified. No permanent state alteration detected.`;

    return {
      dangerScore: maxScore,
      severity,
      category,
      reasons,
      affectedEntities: Array.from(affectedEntities),
      destructive: isDestructive,
      irreversible: isIrreversible,
      rollbackFeasible,
      recommendedMitigations: Array.from(mitigations),
      resolution: {
        resolvedCommand: resolution.resolved,
        traits: resolution.traits,
        hasPipeline: resolution.hasPipeline,
        interpreters: resolution.interpreters,
        unresolvedVariables: resolution.unresolvedVariables
      },
      dryRunSimulation: {
        simulatedOutput,
        affectedItemCount: affectedEntities.size || (isDestructive ? 1 : 0)
      }
    };
  }

  /**
   * Scores facts that a regex over the submitted string cannot express, because
   * they only exist once the command is resolved.
   *
   * These are the GuardFall bypass shapes: a recursive delete aimed through a
   * variable, a delete hidden inside `find`, and content piped into an
   * interpreter. None of them look dangerous as text.
   */
  private static evaluateStructuralTraits(resolution: ResolvedCommand): {
    score: number;
    reasons: string[];
    destructive: boolean;
    irreversible: boolean;
    mitigations: string[];
  } {
    const reasons: string[] = [];
    const mitigations = new Set<string>();
    let score = 0;
    let destructive = false;
    let irreversible = false;

    // A destructive binary pointed at root, home, or a wildcard. Reaching this
    // means the rule layer did not already catch it, so the target is one it does
    // not enumerate.
    const destructiveBinary = resolution.executables.find((e) =>
      ['rm', 'unlink', 'shred', 'srm', 'rmdir'].includes(e)
    );
    if (destructiveBinary) {
      const argumentText = resolution.segments
        .map((s) => s.args.join(' '))
        .join(' ');
      const broadTarget = /(^|\s)(\/|~|\*|\$HOME|UNKNOWN|\/\*)(\s|$)|\/\*|(^|\s)\.\.\/|(^|\s)(\.\.\/)+(\s|$)/.test(argumentText);
      const recursive = /-(r|R|rf|fr|rfz|fR)/.test(argumentText) || destructiveBinary !== 'rm';
      if (broadTarget && recursive) {
        score = Math.max(score, 100);
        destructive = true;
        reasons.push(
          `Recursive ${destructiveBinary} against a broad target (${argumentText.trim() || 'unspecified'}), resolved through variable or substitution expansion.`
        );
        mitigations.add('Target a specific named path, and never a wildcard or a home directory.');
      }
    }

    // `shred` and `srm` overwrite rather than unlink, so the target is not
    // recoverable even without a recursive flag. Any named path counts.
    const forensicallyDestructive = resolution.executables.find((e) => ['shred', 'srm', 'wipe'].includes(e));
    if (forensicallyDestructive) {
      const targets = resolution.segments
        .flatMap((s) => s.args)
        .filter((a) => a && !a.startsWith('-'));
      if (targets.length > 0) {
        score = Math.max(score, 90);
        destructive = true;
        irreversible = true;
        reasons.push(
          `${forensicallyDestructive} overwrites file contents in place, so ${targets.length} target${targets.length === 1 ? '' : 's'} cannot be recovered after the call.`
        );
        mitigations.add('Take a snapshot before any irreversible overwrite, and confirm the target list.');
      }
    }

    // An absolute system path removed recursively is destructive even when it is
    // not root or home. Scratch space is excluded: /tmp and /var/tmp exist to be
    // deleted, and flagging them is how people switch a guardrail off.
    const absoluteSystemPath = resolution.paths.find((p) =>
      /^\/(etc|bin|usr|sbin|boot|lib|opt|sys|proc|dev|srv|root|home|var\/(?!tmp\/?$))([/]|$)/.test(p)
    );
    const recursiveFlag = resolution.segments.some((s) =>
      s.executable.split('/').pop()?.toLowerCase() === 'rm' && s.args.some((a) => /^-[a-zA-Z]*[rR]/.test(a))
    );
    if (absoluteSystemPath && recursiveFlag) {
      score = Math.max(score, 95);
      destructive = true;
      irreversible = true;
      reasons.push(`Recursive removal of a system path (${absoluteSystemPath}).`);
      mitigations.add('System paths are not recoverable without a restore from media.');
    }

    // `find ... -delete` / `find ... -exec rm` destroys without naming the intent
    // in a position a parser would read as a delete.
    if (resolution.traits.includes('find-delete')) {
      score = Math.max(score, 90);
      destructive = true;
      reasons.push('File destruction delegated to `find` via -delete, -exec rm, or -ok.');
      mitigations.add('Print the matched set first and review it before deleting.');
    }

    // Content arriving over a pipe and landing in an interpreter is the
    // download-and-execute shape. No substitution is required for it to be
    // dangerous, so `cat payload.sh | sh` counts the same as `curl ... | sh`.
    if (resolution.traits.includes('piped-to-interpreter')) {
      const target = resolution.interpreters[0];
      if (target) {
        score = Math.max(score, 90);
        destructive = true;
        reasons.push(`Piped content is executed by an interpreter (${target}); the program that runs is never present in the request.`);
        mitigations.add('Write the script to a file, review it, then execute that file.');
      }
    }

    // A destructive variable the resolver could not resolve statically is marked
    // `/UNKNOWN` on purpose. It stands for $HOME, $ROOT, $PWD and friends, so a
    // recursive delete aimed at one is a delete aimed at a root or home path.
    //
    // Only a destructive *binary with a recursive flag* counts. Requiring `-r`
    // is what stops ordinary scripting such as `TARGET=$PWD/build; rm -rf
    // $TARGET` from scoring CRITICAL, which is how a guardrail gets switched off.
    const unknownTarget = resolution.segments.some((s) => {
      const base = (s.executable.split('/').pop() || '').toLowerCase();
      if (!['rm', 'unlink', 'shred', 'srm', 'rmdir'].includes(base)) return false;
      if (base !== 'rm') return s.args.some((a) => a.includes('UNKNOWN'));
      const recursive = s.args.some((a) => /^-[a-zA-Z]*[rR]/.test(a));
      const aimedAtUnknown = s.args.some((a) => a.includes('UNKNOWN'));
      return recursive && aimedAtUnknown;
    });
    if (unknownTarget) {
      score = Math.max(score, 100);
      destructive = true;
      reasons.push(
        'Recursive delete aimed at a variable conventionally holding a root or home path. The value was not available for inspection, so the target cannot be bounded.'
      );
      mitigations.add('Never construct a destructive path from an environment variable.');
    }

    // An interpreter is handed a destructive command it assembled at runtime.
    if (resolution.traits.includes('inline-destructive')) {
      score = Math.max(score, 90);
      destructive = true;
      reasons.push('A destructive command is built inline and executed by an interpreter in one step.');
      mitigations.add('Split the command into reviewable steps rather than composing it inline.');
    }

    // `sh -c "$(curl ...)"` executes whatever the network returns, so the program
    // is unknowable at request time and the call cannot be reviewed by reading it.
    if (resolution.traits.includes('inline-remote-substitution')) {
      score = Math.max(score, 95);
      destructive = true;
      reasons.push('An interpreter is handed a program generated at runtime, so the code that executes is not present in the request.');
      mitigations.add('Fetch the script, store it, review it, then execute the reviewed file.');
    }

    // A path assembled from a character code is a path written specifically to be
    // unread at review time. `T=$(( 0x2f ))` computes the number 47, but the
    // only reason to write `0x2f` as a delete target is the slash it encodes, so
    // the target cannot be bounded by reading the request.
    if (resolution.traits.includes('encoded-path')) {
      score = Math.max(score, 90);
      destructive = true;
      reasons.push('A delete target is assembled from a numeric character code rather than written as a path, so the resolved path cannot be reviewed.');
      mitigations.add('Write the target path literally so it can be read before the command runs.');
    }

    // `xargs` runs arguments it never shows you.
    if (resolution.traits.includes('xargs-exec')) {
      score = Math.max(score, 75);
      reasons.push('Arguments are assembled at runtime by `xargs`, so the real command set is not in the request.');
      mitigations.add('Expand the input list first and confirm it contains nothing destructive.');
    }

    // Bytes are decoded and then executed in one step. The destructive verb never
    // appears as a word, so the literal-verb grep the inline path uses cannot see
    // this; the shape itself is the signal.
    if (resolution.traits.includes('inline-decode-execute')) {
      score = Math.max(score, 90);
      destructive = true;
      reasons.push('An inline program decodes a payload and executes it, so the command that runs is encoded rather than written in the request.');
      mitigations.add('Inline the decoded text so the executed command can be read before it runs.');
    }

    // A process substitution feeding an interpreter is the same unknowable
    // program as a pipe into one, arriving on a file descriptor instead.
    if (resolution.traits.includes('process-substitution-exec')) {
      score = Math.max(score, 90);
      destructive = true;
      reasons.push('A process substitution feeds fetched or decoded content to an interpreter; the program that runs is never present in the request.');
      mitigations.add('Write the fetched content to a file, review it, then execute that file.');
    }

    return { score, reasons, destructive, irreversible, mitigations: Array.from(mitigations) };
  }

  private static structuredDepth = 0;

  /**
   * Scores the string leaves of a serialised MCP parameter object.
   *
   * Returns undefined when the input is not JSON, so ordinary shell commands
   * take the normal path untouched. When it is JSON, every string leaf that
   * plausibly names a command is evaluated independently and the worst report
   * wins: the parameter set is one request, and a destructive call hidden in any
   * field makes the whole request destructive.
   *
   * Free text is excluded deliberately. A `description` or `message` field can
   * mention `rm -rf /` in prose without containing it as a command, and scoring
   * prose is how a guardrail starts blocking ordinary tool calls.
   */
  private static evaluateStructuredParams(
    input: string,
    context?: Record<string, any>
  ): BlastRadiusReport | undefined {
    if (!/^\s*[[{]/.test(input) || !input.endsWith('}')) return undefined;

    // A leaf can itself be a serialised object — `server.ts` hands the engine
    // `JSON.stringify(parameters)` where a field may already hold a serialised
    // payload. Without a depth ceiling that leaf re-enters this method with its
    // own text and recurses forever.
    if (BlastRadiusEngine.structuredDepth >= 3) return undefined;

    let parsed: unknown;
    try {
      parsed = JSON.parse(input);
    } catch {
      return undefined;
    }
    // A bare array or scalar is not a parameter object, and a JSON string is a
    // command the normal path already reads correctly.
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;

    BlastRadiusEngine.structuredDepth += 1;
    try {
      return this.worstLeafReport(parsed as Record<string, unknown>, input, context);
    } finally {
      BlastRadiusEngine.structuredDepth -= 1;
    }
  }

  /**
   * Recursively evaluates string leaves and returns the highest-scoring report.
   */
  private static worstLeafReport(
    node: unknown,
    input: string,
    context: Record<string, any> | undefined
  ): BlastRadiusReport {
    const candidates: string[] = [];

    const walk = (value: unknown, keyHint: string, depth: number): void => {
      if (depth > 6 || candidates.length > 64) return;
      if (typeof value === 'string') {
        if (this.isPlausibleCommandLeaf(value, keyHint)) candidates.push(value);
        return;
      }
      if (Array.isArray(value)) {
        for (const item of value) walk(item, keyHint, depth + 1);
        return;
      }
      if (value !== null && typeof value === 'object') {
        for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
          walk(child, key, depth + 1);
        }
      }
    };

    walk(node, '', 0);

    // The reassembled argv goes first: for `{command:'rm', args:['-rf','/']}` it
    // is the only candidate that reads as the command line the server spawns.
    const reassembled = this.reassembleArgv(node);
    const ordered = [...reassembled, ...candidates.filter((leaf) => !reassembled.includes(leaf))];
    if (ordered.length === 0) {
      return this.evaluate(input, undefined, context);
    }

    let worst: BlastRadiusReport | undefined;
    for (const candidate of ordered) {
      const report = this.evaluate(candidate, undefined, context);
      // `>=` keeps the first leaf on a tie, so a harmless field never displaces
      // an equally-scored real one.
      if (!worst || report.dangerScore >= worst.dangerScore) worst = report;
    }

    if (!worst) {
      // Nothing that reads as a command. Score the serialisation itself, which is
      // what a parameter object with no shell content in it should be worth.
      return this.evaluate(input, undefined, context);
    }

    // The whole parameter set is one request. Naming the field the score came
    // from is what lets a reviewer see that `rm -rf /` arrived as `args[1]`.
    worst.reasons.unshift(
      `Scored from structured tool parameters; the highest-scoring command-bearing field was: ${truncateForReport(worst.resolution?.resolvedCommand || '')}`
    );
    return worst;
  }

  /**
   * Whether a string leaf should be read as a command at all.
   *
   * The length ceiling is the important part. Free-text fields are arbitrarily
   * long and semantically prose; treating one as a command produces a score for
   * text nobody is going to execute.
   */
  private static isPlausibleCommandLeaf(value: string, keyHint: string): boolean {
    const leaf = value.trim();
    if (leaf.length === 0 || leaf.length > 512) return false;
    // Multi-line leaves are scripts, not single tool arguments, and are excluded
    // because the whole point of the walk is to score individual argv entries.
    if (/[\n\r]/.test(leaf)) return false;
    if (keyHint && NON_COMMAND_FIELD.test(keyHint)) return false;

    // A field whose name says it carries a command is trusted as one. This is
    // what catches `{command:'rm', args:['-rf','/']}`.
    if (/^(command|cmd|program|script|shell|exec|argv|args|arguments|commandline|command_or_query|commandOrQuery|entrypoint|run|line)$/i.test(keyHint)) {
      return true;
    }

    // Otherwise the leaf must look like a command on its own: a short token
    // sequence starting with something executable-shaped. Flag-like or
    // path-like fragments (`-rf`, `/var/log`) alone are not commands.
    const tokens = leaf.split(/\s+/);
    if (tokens.length === 0 || tokens.length > 24) return false;
    const first = tokens[0] as string;
    if (/^[-./~]/.test(first)) return false;
    if (!/^[A-Za-z0-9_.\-\\/]+$/.test(first)) return false;
    // A shell metacharacter means the leaf is a compound command, which is
    // worth resolving whether or not the field is named for it.
    return /[;|&><`$]/.test(leaf);
  }

  /**
   * The argv-shaped parameter object is the common MCP case and the one the
   * redteam probe sends: a `command` field naming a binary and an `args` array
   * naming its arguments. Scoring the fields independently cannot see it, because
   * `command: 'rm'` alone is a harmless two-letter word and `args: ['-rf','/']`
   * alone is a flag and a path. Reassembling them is what recovers the command
   * line the server will actually spawn.
   */
  private static reassembleArgv(node: unknown, depth: number = 0): string[] {
    if (depth > 4 || node === null || typeof node !== 'object') return [];
    if (Array.isArray(node)) {
      return node.flatMap((item) => this.reassembleArgv(item, depth + 1));
    }

    const entries = Object.entries(node as Record<string, unknown>);
    const commandEntry = entries.find(([key, value]) =>
      typeof value === 'string' && /^(command|cmd|program|shell|script|commandline|command_or_query|commandOrQuery)$/i.test(key)
    );
    if (commandEntry) {
      const command = (commandEntry[1] as string).trim();
      if (!command) return [];
      const argEntry = entries.find(([key, value]) =>
        Array.isArray(value) && /^(args|argv|arguments|params|flags|options)$/i.test(key)
      );
      const parts: string[] = [command];
      if (argEntry && Array.isArray(argEntry[1])) {
        for (const arg of argEntry[1]) {
          // Only string and number leaves are argv entries. An object in that
          // position is a nested payload, handled by its own walk.
          if (typeof arg === 'string') parts.push(arg);
          else if (typeof arg === 'number' || typeof arg === 'boolean') parts.push(String(arg));
        }
      }
      return [parts.join(' ')];
    }

    return entries.flatMap(([, value]) => this.reassembleArgv(value, depth + 1));
  }

  private static extractAffectedTargets(
    input: string,
    category: ActionCategory,
    entities: Set<string>
  ): void {
    if (category === ActionCategory.SQL) {
      const tableMatch = input.match(/\b(?:FROM|INTO|UPDATE|TABLE)\s+[`"']?([a-zA-Z0-9_.-]+)[`"']?/i);
      if (tableMatch && tableMatch[1]) {
        entities.add(`table:${tableMatch[1]}`);
      }
      const dbMatch = input.match(/\bDATABASE\s+[`"']?([a-zA-Z0-9_.-]+)[`"']?/i);
      if (dbMatch && dbMatch[1]) {
        entities.add(`database:${dbMatch[1]}`);
      }
    } else if (category === ActionCategory.SHELL || category === ActionCategory.FILESYSTEM) {
      const pathMatches = input.matchAll(/(?:\s|^)([\/~.][a-zA-Z0-9_.\-\/\\]+|[a-zA-Z]:\\[a-zA-Z0-9_.\-\/\\]+)/g);
      for (const m of pathMatches) {
        if (m[1] && m[1].length > 1) {
          entities.add(`path:${m[1]}`);
        }
      }
    } else if (category === ActionCategory.CLOUD) {
      const resMatch = input.match(/--(?:instance-ids|bucket|cluster-name|role-name|stack-name)\s+([a-zA-Z0-9_-]+)/i);
      if (resMatch && resMatch[1]) {
        entities.add(`cloud_resource:${resMatch[1]}`);
      }
    }
  }
}
