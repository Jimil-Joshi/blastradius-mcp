import { AuditLedger } from '../security/auditLedger.js';
import {
  ActionCategory,
  AuditEntry,
  PolicyDecision,
  SecurityPolicyConfig,
  SeverityLevel
} from '../types.js';

export type SequencePatternId =
  | 'exfiltration-then-destruction'
  | 'reconnaissance-then-exfiltration'
  | 'privilege-ladder'
  | 'guardrail-probing'
  | 'destructive-burst';

export interface SequenceSignal {
  id: SequencePatternId;
  severity: SeverityLevel;
  confidence: number; // 0..1
  reason: string; // specific, cites the indices that triggered it
  evidence: {
    fromIndex: number;
    toIndex: number;
    toolNames: string[];
    /** Number of decisions that satisfied the pattern predicate inside the span. */
    decisionCount: number;
  };
  recommendedAction: 'ESCALATE_TO_CONFIRMATION' | 'ESCALATE_TO_BLOCK' | 'FLAG_FOR_REVIEW';
}

export interface SequenceAnalysis {
  signals: SequenceSignal[];
  highestSeverity: SeverityLevel;
  analysedEntries: number;
  /**
   * Set when analysis ran over a truncated window and could therefore miss
   * patterns that begin before the window. Honest about what was not seen.
   */
  truncated: boolean;
}

export interface SequenceDetectorOptions {
  /** Master switch. False means analyze() returns an empty result. */
  enabled?: boolean;
  /** Decisions inspected, most recent last. Patterns may not start before this. */
  windowSize?: number;
  /** Destructive decisions inside burstWindowSize required for destructive-burst. */
  destructiveBurstThreshold?: number;
  /** Refusals against one tool family required for guardrail-probing. */
  probingThreshold?: number;
  /** Distinct privilege operation families required for privilege-ladder. */
  privilegeLadderThreshold?: number;
  /** Read-type calls in a run required for reconnaissance-then-exfiltration. */
  reconThreshold?: number;
  /** Distinct inputHash values the recon run must touch. */
  reconDistinctResources?: number;
  /** dlpFindingsCount at which a call counts as an exfiltration sink. */
  exfilDlpThreshold?: number;
  /** Decision span the destructive burst is measured over. */
  burstWindowSize?: number;
  /** Strictly rising dangerScore calls to one tool required for the ladder. */
  escalationRepeatThreshold?: number;
  /** Seconds over which a burst still counts as speed rather than history. */
  burstSeconds?: number;
  /** Minimum severity for a decision to count as destructive. */
  destructiveSeverityFloor?: SeverityLevel;
  /** Minimum dangerScore for a decision to count as destructive. */
  destructiveScoreFloor?: number;
  /** Hard ceiling on every confidence value this detector emits. */
  maxConfidence?: number;
  /** Ceiling on how many signals one pattern may contribute to a result. */
  maxSignalsPerPattern?: number;
}

/** Per-call overrides. ledgerLimit only applies to analyzeFromLedger. */
export interface SequenceAnalyzeOptions extends SequenceDetectorOptions {
  /** Entries read from the ledger. Defaults to DEFAULT_LEDGER_READ_LIMIT. */
  ledgerLimit?: number;
}

type ResolvedOptions = Required<Omit<SequenceDetectorOptions, 'enabled'>>;

export const DEFAULT_SEQUENCE_OPTIONS: ResolvedOptions = {
  // 20 decisions: long enough to hold a staging run plus a payload, short enough
  // that a busy session still sees the shape rather than a slice of an hour.
  windowSize: 20,
  // 4 destructive calls inside one burst span. The 2026 incidents were speed,
  // and a single destructive call is a maintenance task.
  destructiveBurstThreshold: 4,
  burstWindowSize: 8,
  // 3 refusals against one tool family. Two are an agent asking again.
  probingThreshold: 3,
  // 3 distinct privilege operations. Two is provisioning.
  privilegeLadderThreshold: 3,
  // 5 reads before the send. Below this the run is not reconnaissance.
  reconThreshold: 5,
  // 3 distinct payloads, so the run is spreading rather than re-reading one thing.
  reconDistinctResources: 3,
  // 2 DLP findings, since a single finding is one field in a large payload.
  exfilDlpThreshold: 2,
  escalationRepeatThreshold: 3,
  // 120s: long enough for a scripted agent, short enough to mean "right now".
  burstSeconds: 120,
  destructiveSeverityFloor: SeverityLevel.HIGH,
  destructiveScoreFloor: 70,
  maxConfidence: 0.95,
  maxSignalsPerPattern: 3
};

const DEFAULT_LEDGER_READ_LIMIT = 500;

const SEVERITY_ORDER: SeverityLevel[] = [
  SeverityLevel.SAFE,
  SeverityLevel.LOW,
  SeverityLevel.MEDIUM,
  SeverityLevel.HIGH,
  SeverityLevel.CRITICAL
];

function severityRank(severity: SeverityLevel): number {
  const rank = SEVERITY_ORDER.indexOf(severity);
  return rank === -1 ? 0 : rank;
}

function reasonsOf(entry: AuditEntry): string {
  return Array.isArray(entry.reasons) ? entry.reasons.join(' ') : '';
}

function scoreOf(entry: AuditEntry): number {
  return entry.dangerScore ?? 0;
}

function dlpOf(entry: AuditEntry): number {
  return entry.dlpFindingsCount ?? 0;
}

function clamp(value: number, ceiling: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(ceiling, Math.max(0, Number(value.toFixed(2))));
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.length > 0)));
}

/**
 * Destructive or irreversible phrasing, as emitted by DANGEROUS_RULES and by the
 * structural traits in BlastRadiusEngine. The ledger stores reasons verbatim, so
 * matching on them keeps the classification anchored to what the engine decided
 * rather than to a guess about the payload we no longer hold.
 */
const DESTRUCTIVE_MARKERS =
  /(delet|remov|destroy|destruct|drop\b|dropped|truncat|terminat|purge|overwrit|wip|shred|unlink|teardown|irreversib|unrecoverab|cannot be recovered|not recoverable|code loss|offline|data loss|force[- ]push|hard reset)/i;

/**
 * An AuditEntry carries severity and dangerScore but not the destructive and
 * irreversible flags themselves. Both are reconstructed here from the severity
 * floor, the score floor, and the engine's own wording.
 */
function isDestructive(entry: AuditEntry, cfg: ResolvedOptions): boolean {
  if (severityRank(entry.severity) < severityRank(cfg.destructiveSeverityFloor)) return false;
  if (scoreOf(entry) < cfg.destructiveScoreFloor) return false;
  if (DESTRUCTIVE_MARKERS.test(reasonsOf(entry))) return true;
  // In SHELL, SQL, CLOUD and FILESYSTEM a CRITICAL score is only reachable
  // through a destructive or irreversible rule, so the wording is a fallback.
  if (entry.severity === SeverityLevel.CRITICAL && scoreOf(entry) >= 90) return true;
  return false;
}

const SECRET_TOOL =
  /(\.env|credential|secret|token|api[\s_-]?key|password|passwd|id_rsa|id_ed25519|\.pem|private[\s_-]?key|keychain|vault|keystore|oauth|session[\s_-]?(?:token|cookie))/i;
const SECRET_REASON =
  /(sensitive credential|secret|credential|auth file|api[\s_-]?key|private key|\.env|\/etc\/shadow|passwd|id_rsa|service[\s_-]?account|keychain|vault)/i;

/**
 * A credential-adjacent read, as opposed to a credential-adjacent deletion. The
 * rule layer calls both "access to sensitive credentials", so the destructive
 * test runs first to keep the two apart.
 */
function isSecretRead(entry: AuditEntry, cfg: ResolvedOptions): boolean {
  if (isDestructive(entry, cfg)) return false;
  if (dlpOf(entry) > 0) return true;
  return SECRET_TOOL.test(entry.toolName ?? '') || SECRET_REASON.test(reasonsOf(entry));
}

const READ_INTENT =
  /^(read|get|list|fetch|cat|open|describe|inspect|show|query|select|env|getenv|whoami|export|print|dump|view|copy|download|search|find|stat|ls|resolve|validate|verify|head|tail|grep)/i;

function isReadLike(entry: AuditEntry, cfg: ResolvedOptions): boolean {
  if (isDestructive(entry, cfg)) return false;
  if (scoreOf(entry) <= 25 && severityRank(entry.severity) <= severityRank(SeverityLevel.LOW)) {
    return true;
  }
  return READ_INTENT.test(entry.toolName ?? '') || /\b(select|read|list|describe|inspect)\b/i.test(reasonsOf(entry));
}

// Bounded on purpose: `list_posts` is a read, `send_post` is egress.
const EGRESS_TOOL =
  /(^|[_:-])(send|post|upload|publish|email|mail|slack|webhook|discord|telegram|curl|wget|paste|share|transmit|forward|exfil)([_:-]|$)/i;

function isExfilSink(entry: AuditEntry, cfg: ResolvedOptions): boolean {
  if (entry.category === ActionCategory.NETWORK) return true;
  if (dlpOf(entry) >= cfg.exfilDlpThreshold) return true;
  return EGRESS_TOOL.test(entry.toolName ?? '');
}

/**
 * Privilege-granting families, tested in order so each call maps to exactly one.
 * The ladder is scored on how many distinct families were approved, not on how
 * many calls, because a single rule already catches `GRANT ALL` on its own.
 */
const PRIVILEGE_FAMILIES: { key: string; pattern: RegExp }[] = [
  { key: 'grant-all', pattern: /grant\s+all/i },
  {
    key: 'create-identity',
    pattern: /create[\s_-]*(user|role|policy|group|service[\s_-]?account|api[\s_-]?key)/i
  },
  {
    key: 'attach-role',
    pattern: /(attach|bind|add|set)[\s_-]*(iam|role|policy)|set[\s_-]?iam[\s_-]?policy/i
  },
  { key: 'permissive-mode', pattern: /chmod\s*[-/]?R?\s*(777|666)|a\+rwx/i },
  { key: 'assume-role', pattern: /assume[\s_-]?role|impersonat/i },
  { key: 'acl-write', pattern: /set[\s_-]?acl|add[\s_-]?permission|write\s*=\s*all/i },
  { key: 'elevation', pattern: /privilege escalation|\bsudo\b|superuser|elevat/i }
];

function privilegeFamily(entry: AuditEntry): string | undefined {
  const text = `${entry.toolName ?? ''} ${reasonsOf(entry)}`;
  return PRIVILEGE_FAMILIES.find((family) => family.pattern.test(text))?.key;
}

/**
 * Tools are related when they share a leading segment, so `read_file` and
 * `read_dir` are one family and `delete_bucket` and `delete_key` are another.
 */
function toolFamily(toolName: string): string {
  const cleaned = (toolName ?? '').trim().toLowerCase().replace(/^mcp[_-]+/, '');
  const head = cleaned.split(/[_.:/-]/)[0] ?? '';
  if (head.length > 0) return head;
  return cleaned.length > 0 ? cleaned : 'unknown';
}

function isRefusal(entry: AuditEntry): boolean {
  return entry.decision === PolicyDecision.BLOCK || entry.decision === PolicyDecision.REQUIRE_CONFIRMATION;
}

/**
 * Detects workflow shapes assembled from individually permitted steps.
 *
 * Every per-call rule judges one decision in isolation, so a multi-step attack
 * whose steps each look reasonable passes. This reads the decision history and
 * looks only for *orderings*: a read that precedes a destroy, a staging run that
 * precedes a send, refusals that repeat, destruction that clusters. Nothing here
 * fires because a window happens to be large.
 *
 * The class is pure with respect to its input. analyze() takes the entries as an
 * argument; analyzeFromLedger() is a convenience over AuditLedger.getEntries()
 * for callers that have no other handle on the history.
 */
export class SequenceDetector {
  private readonly cfg: ResolvedOptions;
  private readonly enabled: boolean;

  constructor(options: SequenceDetectorOptions = {}) {
    const d = DEFAULT_SEQUENCE_OPTIONS;
    this.cfg = {
      windowSize: options.windowSize ?? d.windowSize,
      destructiveBurstThreshold: options.destructiveBurstThreshold ?? d.destructiveBurstThreshold,
      probingThreshold: options.probingThreshold ?? d.probingThreshold,
      privilegeLadderThreshold: options.privilegeLadderThreshold ?? d.privilegeLadderThreshold,
      reconThreshold: options.reconThreshold ?? d.reconThreshold,
      reconDistinctResources: options.reconDistinctResources ?? d.reconDistinctResources,
      exfilDlpThreshold: options.exfilDlpThreshold ?? d.exfilDlpThreshold,
      burstWindowSize: options.burstWindowSize ?? d.burstWindowSize,
      escalationRepeatThreshold: options.escalationRepeatThreshold ?? d.escalationRepeatThreshold,
      burstSeconds: options.burstSeconds ?? d.burstSeconds,
      destructiveSeverityFloor: options.destructiveSeverityFloor ?? d.destructiveSeverityFloor,
      destructiveScoreFloor: options.destructiveScoreFloor ?? d.destructiveScoreFloor,
      maxConfidence: options.maxConfidence ?? d.maxConfidence,
      maxSignalsPerPattern: options.maxSignalsPerPattern ?? d.maxSignalsPerPattern
    };
    this.enabled = options.enabled !== false;
  }

  /**
   * Builds a detector from the policy config, so sequence analysis is switched on
   * and off by the same document that carries the rest of the security posture.
   */
  public static fromPolicy(config?: SecurityPolicyConfig): SequenceDetector {
    const sequence = config?.sequence;
    return new SequenceDetector({
      enabled: sequence?.enabled,
      windowSize: sequence?.windowSize,
      destructiveBurstThreshold: sequence?.destructiveBurstThreshold,
      probingThreshold: sequence?.probingThreshold
    });
  }

  /**
   * Analyses a decision history. Entries are ordered by their ledger index, and
   * only the most recent `windowSize` of them are inspected.
   */
  public analyze(entries: AuditEntry[], options: SequenceAnalyzeOptions = {}): SequenceAnalysis {
    if (!this.enabled) {
      return {
        signals: [],
        highestSeverity: SeverityLevel.SAFE,
        analysedEntries: 0,
        truncated: false
      };
    }

    const cfg: ResolvedOptions = {
      ...this.cfg,
      windowSize: options.windowSize ?? this.cfg.windowSize,
      destructiveBurstThreshold:
        options.destructiveBurstThreshold ?? this.cfg.destructiveBurstThreshold,
      probingThreshold: options.probingThreshold ?? this.cfg.probingThreshold
    };

    const ordered = [...(entries ?? [])].sort((a, b) => a.index - b.index);
    const analysed = ordered.length > cfg.windowSize ? ordered.slice(-cfg.windowSize) : ordered;
    const truncated =
      ordered.length > analysed.length || (analysed.length > 0 && analysed[0].index > 0);

    const signals: SequenceSignal[] = [];
    this.detectExfiltrationThenDestruction(analysed, cfg, signals);
    this.detectReconnaissanceThenExfiltration(analysed, cfg, signals);
    this.detectPrivilegeLadder(analysed, cfg, signals);
    this.detectGuardrailProbing(analysed, cfg, signals);
    this.detectDestructiveBurst(analysed, cfg, signals);

    signals.sort((a, b) => {
      const bySeverity = severityRank(b.severity) - severityRank(a.severity);
      if (bySeverity !== 0) return bySeverity;
      const byConfidence = b.confidence - a.confidence;
      if (byConfidence !== 0) return byConfidence;
      return a.evidence.fromIndex - b.evidence.fromIndex;
    });

    return {
      signals: this.capPerPattern(signals, cfg.maxSignalsPerPattern),
      highestSeverity:
        signals.length > 0 ? signals[0].severity : SeverityLevel.SAFE,
      analysedEntries: analysed.length,
      truncated
    };
  }

  /**
   * Analyses the most recent entries in the live audit ledger. `truncated` is set
   * whenever the ledger holds decisions the analysis did not reach, so a caller
   * never reads an empty result as proof that nothing happened earlier.
   */
  public analyzeFromLedger(options: SequenceAnalyzeOptions = {}): SequenceAnalysis {
    const entries = AuditLedger.getEntries(options.ledgerLimit ?? DEFAULT_LEDGER_READ_LIMIT);
    return this.analyze(entries, options);
  }

  private capPerPattern(signals: SequenceSignal[], limit: number): SequenceSignal[] {
    if (limit <= 0) return signals;
    const seen = new Map<SequencePatternId, number>();
    const kept: SequenceSignal[] = [];
    for (const signal of signals) {
      const count = seen.get(signal.id) ?? 0;
      if (count >= limit) continue;
      seen.set(signal.id, count + 1);
      kept.push(signal);
    }
    return kept;
  }

  /**
   * exfiltration-then-destruction: the nearest preceding credential read inside
   * the window, for each destructive decision. Fires only when the read strictly
   * precedes the destroy; the reverse order is not this shape.
   */
  private detectExfiltrationThenDestruction(
    entries: AuditEntry[],
    cfg: ResolvedOptions,
    out: SequenceSignal[]
  ): void {
    for (let i = 0; i < entries.length; i++) {
      const destructive = entries[i];
      if (!isDestructive(destructive, cfg)) continue;

      let read: AuditEntry | undefined;
      let readPosition = -1;
      for (let j = i - 1; j >= 0; j--) {
        if (isSecretRead(entries[j], cfg)) {
          read = entries[j];
          readPosition = j;
          break;
        }
      }
      if (!read) continue;

      const gap = i - readPosition;
      const severity =
        severityRank(destructive.severity) >= severityRank(SeverityLevel.CRITICAL)
          ? SeverityLevel.CRITICAL
          : SeverityLevel.HIGH;
      const confidence = clamp(
        0.8 + (gap <= 3 ? 0.1 : 0) + (dlpOf(read) > 0 ? 0.05 : 0),
        cfg.maxConfidence
      );

      out.push({
        id: 'exfiltration-then-destruction',
        severity,
        confidence,
        reason:
          `Credential-adjacent read of ${read.toolName} at index ${read.index} ` +
          `(${dlpOf(read)} DLP finding(s)) is followed ${gap} decision(s) later by ` +
          `${destructive.toolName} at index ${destructive.index} ` +
          `(severity ${destructive.severity}, danger ${scoreOf(destructive)}). ` +
          'Each step is permitted on its own; the ordering is not.',
        evidence: {
          fromIndex: read.index,
          toIndex: destructive.index,
          toolNames: unique([read.toolName, destructive.toolName]),
          decisionCount: 2
        },
        recommendedAction:
          severity === SeverityLevel.CRITICAL ? 'ESCALATE_TO_BLOCK' : 'ESCALATE_TO_CONFIRMATION'
      });
    }
  }

  /**
   * reconnaissance-then-exfiltration: a contiguous run of read-type calls
   * touching several distinct payloads, immediately followed by a network
   * category or DLP-heavy call. The run must end at the sink, so the staging
   * provably precedes the send.
   */
  private detectReconnaissanceThenExfiltration(
    entries: AuditEntry[],
    cfg: ResolvedOptions,
    out: SequenceSignal[]
  ): void {
    for (let i = 0; i < entries.length; i++) {
      const sink = entries[i];
      if (!isExfilSink(sink, cfg)) continue;

      const recon: AuditEntry[] = [];
      for (let j = i - 1; j >= 0; j--) {
        if (!isReadLike(entries[j], cfg)) break;
        recon.unshift(entries[j]);
      }
      if (recon.length < cfg.reconThreshold) continue;

      const distinctInputs = new Set(recon.map((entry) => entry.inputHash));
      if (distinctInputs.size < cfg.reconDistinctResources) continue;

      const distinctTools = new Set(recon.map((entry) => entry.toolName));
      const severity = dlpOf(sink) > 0 ? SeverityLevel.HIGH : SeverityLevel.MEDIUM;
      const confidence = clamp(
        0.6 +
          0.05 * Math.min(4, recon.length - cfg.reconThreshold) +
          0.05 * Math.min(4, distinctInputs.size - cfg.reconDistinctResources),
        Math.min(cfg.maxConfidence, 0.85)
      );

      out.push({
        id: 'reconnaissance-then-exfiltration',
        severity,
        confidence,
        reason:
          `${recon.length} read-type calls over ${distinctInputs.size} distinct payloads ` +
          `across ${distinctTools.size} tool(s) run from index ${recon[0].index} to ` +
          `index ${recon[recon.length - 1].index}, then ${sink.toolName} at index ` +
          `${sink.index} egresses (category ${sink.category}, ${dlpOf(sink)} DLP finding(s)). ` +
          'Staging then sending, which no single-call rule can see.',
        evidence: {
          fromIndex: recon[0].index,
          toIndex: sink.index,
          toolNames: unique([...recon.map((entry) => entry.toolName), sink.toolName]),
          decisionCount: recon.length + 1
        },
        recommendedAction:
          severity === SeverityLevel.HIGH ? 'ESCALATE_TO_CONFIRMATION' : 'FLAG_FOR_REVIEW'
      });
    }
  }

  /**
   * privilege-ladder: either distinct privilege-granting families approved with
   * non-decreasing severity in window order, or one tool called repeatedly with
   * strictly rising dangerScore and an elevated terminal decision.
   */
  private detectPrivilegeLadder(
    entries: AuditEntry[],
    cfg: ResolvedOptions,
    out: SequenceSignal[]
  ): void {
    const grants = entries.filter((entry) => privilegeFamily(entry) !== undefined);
    let run: AuditEntry[] = [];

    const flush = (): void => {
      if (run.length === 0) return;
      const families = unique(run.map((entry) => privilegeFamily(entry) ?? ''));
      if (families.length >= cfg.privilegeLadderThreshold) {
        const severity =
          families.length >= cfg.privilegeLadderThreshold + 2
            ? SeverityLevel.CRITICAL
            : SeverityLevel.HIGH;
        out.push({
          id: 'privilege-ladder',
          severity,
          confidence: clamp(
            0.75 + 0.05 * Math.min(4, families.length - cfg.privilegeLadderThreshold),
            cfg.maxConfidence
          ),
          reason:
            `${families.length} distinct privilege operations (${families.join(', ')}) were ` +
            `approved in non-decreasing severity between index ${run[0].index} and index ` +
            `${run[run.length - 1].index} (${run
              .map((entry) => `${entry.toolName}@${entry.index}:${entry.severity}`)
              .join(' -> ')}). A per-call rule sees each grant as a single request; ` +
            'the ladder is the accumulation.',
          evidence: {
            fromIndex: run[0].index,
            toIndex: run[run.length - 1].index,
            toolNames: unique(run.map((entry) => entry.toolName)),
            decisionCount: run.length
          },
          recommendedAction:
            severity === SeverityLevel.CRITICAL ? 'ESCALATE_TO_BLOCK' : 'ESCALATE_TO_CONFIRMATION'
        });
      }
      run = [];
    };

    for (const entry of grants) {
      const previous = run[run.length - 1];
      if (!previous || severityRank(entry.severity) >= severityRank(previous.severity)) {
        run.push(entry);
      } else {
        flush();
        run = [entry];
      }
    }
    flush();

    const byTool = new Map<string, AuditEntry[]>();
    for (const entry of entries) {
      const list = byTool.get(entry.toolName);
      if (list) list.push(entry);
      else byTool.set(entry.toolName, [entry]);
    }

    for (const [toolName, calls] of byTool) {
      if (calls.length < cfg.escalationRepeatThreshold) continue;
      let best: AuditEntry[] = [];
      let current: AuditEntry[] = [];
      for (const call of calls) {
        const previous = current[current.length - 1];
        if (!previous || scoreOf(call) > scoreOf(previous)) current.push(call);
        else current = [call];
        if (current.length > best.length) best = current;
      }
      if (best.length < cfg.escalationRepeatThreshold) continue;
      const terminal = best[best.length - 1];
      // Without this a run of ordinary reads of growing size would be a ladder.
      if (severityRank(terminal.severity) < severityRank(SeverityLevel.HIGH)) continue;

      out.push({
        id: 'privilege-ladder',
        severity: SeverityLevel.HIGH,
        confidence: clamp(
          0.7 + 0.05 * Math.min(4, best.length - cfg.escalationRepeatThreshold),
          cfg.maxConfidence
        ),
        reason:
          `${toolName} was called ${best.length} times with strictly rising dangerScore ` +
          `between index ${best[0].index} and index ${terminal.index} ` +
          `(${best.map((entry) => `${entry.index}:${scoreOf(entry)}`).join(' -> ')}), ` +
          `terminating on a ${terminal.severity} decision. Same tool, escalating arguments.`,
        evidence: {
          fromIndex: best[0].index,
          toIndex: terminal.index,
          toolNames: [toolName],
          decisionCount: best.length
        },
        recommendedAction: 'ESCALATE_TO_CONFIRMATION'
      });
    }
  }

  /**
   * guardrail-probing: repeated refusals against one tool family. The evidence is
   * the refusal run itself, so the signal says which family is being hunted.
   */
  private detectGuardrailProbing(
    entries: AuditEntry[],
    cfg: ResolvedOptions,
    out: SequenceSignal[]
  ): void {
    const families = new Map<string, AuditEntry[]>();
    for (const entry of entries) {
      if (!isRefusal(entry)) continue;
      const family = toolFamily(entry.toolName);
      const list = families.get(family);
      if (list) list.push(entry);
      else families.set(family, [entry]);
    }

    for (const [family, refusals] of families) {
      if (refusals.length < cfg.probingThreshold) continue;
      const blocks = refusals.filter((entry) => entry.decision === PolicyDecision.BLOCK).length;
      const severity =
        refusals.length >= cfg.probingThreshold + 2
          ? SeverityLevel.CRITICAL
          : blocks > 0
            ? SeverityLevel.HIGH
            : SeverityLevel.MEDIUM;
      const first = refusals[0];
      const last = refusals[refusals.length - 1];

      out.push({
        id: 'guardrail-probing',
        severity,
        confidence: clamp(
          0.6 + 0.05 * Math.min(4, refusals.length - cfg.probingThreshold),
          Math.min(cfg.maxConfidence, 0.9)
        ),
        reason:
          `${refusals.length} refusals against the '${family}' tool family between index ` +
          `${first.index} and index ${last.index} (${blocks} BLOCK, ` +
          `${refusals.length - blocks} REQUIRE_CONFIRMATION; tools: ` +
          `${unique(refusals.map((entry) => entry.toolName)).join(', ')}). ` +
          'An agent that keeps being refused is looking for an unguarded equivalent.',
        evidence: {
          fromIndex: first.index,
          toIndex: last.index,
          toolNames: unique(refusals.map((entry) => entry.toolName)),
          decisionCount: refusals.length
        },
        recommendedAction:
          severity === SeverityLevel.CRITICAL
            ? 'ESCALATE_TO_BLOCK'
            : severity === SeverityLevel.HIGH
              ? 'ESCALATE_TO_CONFIRMATION'
              : 'FLAG_FOR_REVIEW'
      });
    }
  }

  /**
   * destructive-burst: at least `destructiveBurstThreshold` destructive decisions
   * inside a span of `burstWindowSize` decisions. Overlapping spans are consumed
   * rather than re-reported, so a single run yields one signal. Confidence rises
   * when the run also happened fast, which is the failure mode in the incidents.
   */
  private detectDestructiveBurst(
    entries: AuditEntry[],
    cfg: ResolvedOptions,
    out: SequenceSignal[]
  ): void {
    let start = 0;
    while (start < entries.length) {
      const span = entries.slice(start, start + cfg.burstWindowSize);
      const hits = span.filter((entry) => isDestructive(entry, cfg));
      if (hits.length >= cfg.destructiveBurstThreshold) {
        const first = hits[0];
        const last = hits[hits.length - 1];
        const spanSeconds = spanSecondsBetween(first, last);
        const fast = spanSeconds !== undefined && spanSeconds <= cfg.burstSeconds;
        const severity =
          hits.length >= cfg.destructiveBurstThreshold + 2
            ? SeverityLevel.CRITICAL
            : SeverityLevel.HIGH;

        out.push({
          id: 'destructive-burst',
          severity,
          confidence: clamp(
            0.7 + 0.05 * Math.min(4, hits.length - cfg.destructiveBurstThreshold) + (fast ? 0.1 : 0),
            cfg.maxConfidence
          ),
          reason:
            `${hits.length} destructive or irreversible decisions in a span of ${span.length} ` +
            `decisions, from index ${first.index} (${first.toolName}) to index ${last.index} ` +
            `(${last.toolName})` +
            (spanSeconds === undefined
              ? '.'
              : `, ${Math.round(spanSeconds)}s apart${fast ? ' - speed, not history' : ''}.`) +
            ' Each call is individually approved; together they are an incident.',
          evidence: {
            fromIndex: first.index,
            toIndex: last.index,
            toolNames: unique(hits.map((entry) => entry.toolName)),
            decisionCount: hits.length
          },
          recommendedAction:
            severity === SeverityLevel.CRITICAL ? 'ESCALATE_TO_BLOCK' : 'ESCALATE_TO_CONFIRMATION'
        });

        // Resume after the burst rather than re-reporting the same run. The
        // fallback keeps the walk moving even if the span was not drawn from
        // this exact array.
        const resume = entries.indexOf(last);
        start = resume === -1 ? start + 1 : resume + 1;
        continue;
      }
      start += 1;
    }
  }
}

/**
 * Wall-clock seconds between two entries, or undefined when either timestamp is
 * unusable. Used only to raise confidence, never to decide whether to fire.
 */
function spanSecondsBetween(first: AuditEntry, last: AuditEntry): number | undefined {
  const from = Date.parse(first.timestamp ?? '');
  const to = Date.parse(last.timestamp ?? '');
  if (Number.isNaN(from) || Number.isNaN(to)) return undefined;
  return Math.abs(to - from) / 1000;
}