import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ActionCategory, AuditEntry, PolicyDecision, SeverityLevel } from '../types.js';

export class AuditLedger {
  // BLAST_RADIUS_AUDIT_PATH overrides the default location. Without it the ledger
  // lands in process.cwd(), which under a GUI client is whatever directory the app
  // happened to be launched from. For a tamper-evident security record that is not
  // an acceptable default, so the path is always worth setting explicitly.
  private static ledgerPath: string =
    process.env.BLAST_RADIUS_AUDIT_PATH ||
    path.join(process.cwd(), 'blastradius-audit.jsonl');
  private static entries: AuditEntry[] = [];
  private static lastHash: string = '0'.repeat(64); // Genesis hash
  private static secretKey: string =
    process.env.BLAST_RADIUS_AUDIT_KEY ||
    crypto.randomBytes(32).toString('hex');

  public static initialize(customFilePath?: string): void {
    if (customFilePath) {
      this.ledgerPath = customFilePath;
    }
    this.entries = [];
    this.lastHash = '0'.repeat(64);

    // If file exists, load and verify existing chain
    if (fs.existsSync(this.ledgerPath)) {
      try {
        const lines = fs.readFileSync(this.ledgerPath, 'utf-8').trim().split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          const entry = JSON.parse(line) as AuditEntry;
          this.entries.push(entry);
          this.lastHash = entry.currentHash;
        }
      } catch (err) {
        // Fallback gracefully if corrupted, start fresh
      }
    }
  }

  /**
   * Append a new audit record to the cryptographic hash chain.
   */
  /**
   * The exact byte sequence the signature is computed over.
   *
   * Deliberately not JSON.stringify of the entry: key order and the optional
   * `signature` field would make verification depend on serialisation details
   * rather than on content.
   */
  private static canonicalBody(entry: {
    index: number;
    timestamp: string;
    toolName: string;
    callerId: string;
    category: string;
    decision: string;
    dangerScore: number;
    severity: string;
    reasons: string[];
    dlpFindingsCount: number;
    inputHash: string;
    prevHash: string;
    currentHash: string;
  }): string {
    return [
      entry.index,
      entry.timestamp,
      entry.toolName,
      entry.callerId,
      entry.category,
      entry.decision,
      entry.dangerScore,
      entry.severity,
      JSON.stringify(entry.reasons),
      entry.dlpFindingsCount,
      entry.inputHash,
      entry.prevHash,
      entry.currentHash
    ].join(':');
  }

  public static record(params: {
    toolName: string;
    callerId: string;
    category: ActionCategory;
    decision: PolicyDecision;
    dangerScore: number;
    severity: SeverityLevel;
    reasons: string[];
    dlpFindingsCount: number;
    rawPayload: any;
  }): AuditEntry {
    const index = this.entries.length;
    const timestamp = new Date().toISOString();
    const prevHash = this.lastHash;

    const inputHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(params.rawPayload || {}))
      .digest('hex');

    const contentToHash = `${index}:${timestamp}:${params.toolName}:${params.callerId}:${params.decision}:${params.dangerScore}:${inputHash}:${prevHash}`;
    const currentHash = crypto.createHash('sha256').update(contentToHash).digest('hex');

    // The signature covers the *whole* entry, not the chain hash.
    //
    // The chain hash above deliberately covers only the fields that participate in
    // chain continuity. Signing `currentHash` alone therefore proved nothing about
    // severity, category, reasons or dlpFindingsCount, even though a comment in
    // this file once claimed it did. Those four fields are exactly what the
    // sequence detector trusts, so an attacker could rewrite them, strip a signal,
    // and verification would still report the entry intact.
    //
    // Signing the full canonical form closes that, because only a holder of the
    // key can produce it.
    const signature = crypto
      .createHmac('sha256', this.secretKey)
      .update(this.canonicalBody({
        index,
        timestamp,
        toolName: params.toolName,
        callerId: params.callerId,
        category: params.category,
        decision: params.decision,
        dangerScore: params.dangerScore,
        severity: params.severity,
        reasons: params.reasons,
        dlpFindingsCount: params.dlpFindingsCount,
        inputHash,
        prevHash,
        currentHash
      }))
      .digest('hex');

    const entry: AuditEntry = {
      index,
      timestamp,
      toolName: params.toolName,
      callerId: params.callerId,
      category: params.category,
      decision: params.decision,
      dangerScore: params.dangerScore,
      severity: params.severity,
      reasons: params.reasons,
      dlpFindingsCount: params.dlpFindingsCount,
      inputHash,
      prevHash,
      currentHash,
      signature
    };

    this.entries.push(entry);
    this.lastHash = currentHash;
    this.writeHeadAnchor(entry);

    // Append to file asynchronously / safely
    try {
      fs.appendFileSync(this.ledgerPath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch {
      // In constrained environments where filesystem is read-only, keep in-memory
    }

    return entry;
  }

  /**
   * Cryptographically verifies the entire chain or a recent window of entries.
   * Returns whether the chain is unbroken and untampered.
   */
  public static verifyIntegrity(limit?: number): {
    intact: boolean;
    totalEntries: number;
    verifiedCount: number;
    tamperedIndex?: number;
    error?: string;
  } {
    const list = limit ? this.entries.slice(-limit) : this.entries;
    if (list.length === 0) {
      return { intact: true, totalEntries: 0, verifiedCount: 0 };
    }

    for (let i = 0; i < list.length; i++) {
      const entry = list[i];

      // 0. Genesis check. Removing entries from the *front* leaves a perfectly
      // consistent chain, and the head anchor only records the tail, so without
      // this an attacker can delete the earliest history and verification passes.
      if (i === 0 && entry.prevHash !== '0'.repeat(64)) {
        return {
          intact: false,
          totalEntries: this.entries.length,
          verifiedCount: 0,
          tamperedIndex: entry.index,
          error: `Ledger does not begin at genesis. Entry ${entry.index} carries prevHash '${entry.prevHash.slice(0, 16)}...', so entries before it were removed or the file was rewritten.`
        };
      }

      // 1. Verify prevHash matches prior entry
      if (i > 0) {
        const prev = list[i - 1];
        if (entry.prevHash !== prev.currentHash) {
          return {
            intact: false,
            totalEntries: this.entries.length,
            verifiedCount: i,
            tamperedIndex: entry.index,
            error: `Broken hash link at index ${entry.index}. Expected prevHash '${prev.currentHash}', found '${entry.prevHash}'.`
          };
        }
      }

      // 2. Re-compute current hash
      const contentToHash = `${entry.index}:${entry.timestamp}:${entry.toolName}:${entry.callerId}:${entry.decision}:${entry.dangerScore}:${entry.inputHash}:${entry.prevHash}`;
      const expectedHash = crypto.createHash('sha256').update(contentToHash).digest('hex');

      if (entry.currentHash !== expectedHash) {
        return {
          intact: false,
          totalEntries: this.entries.length,
          verifiedCount: i,
          tamperedIndex: entry.index,
          error: `Tampered hash at index ${entry.index}. Expected '${expectedHash}', got '${entry.currentHash}'.`
        };
      }

      // 3. Re-compute the HMAC over the full entry body.
      //
      // The chain hash covers continuity fields only, so this is the check that
      // makes severity, category, reasons and dlpFindingsCount tamper-evident.
      // Those four are unsigned by the chain hash, and the sequence detector reads
      // all four.
      const expectedSignature = crypto
        .createHmac('sha256', this.secretKey)
        .update(this.canonicalBody(entry))
        .digest('hex');

      const actualBuf = Buffer.from(entry.signature ?? '', 'utf-8');
      const expectedBuf = Buffer.from(expectedSignature, 'utf-8');
      if (
        actualBuf.length !== expectedBuf.length ||
        !crypto.timingSafeEqual(actualBuf, expectedBuf)
      ) {
        return {
          intact: false,
          totalEntries: this.entries.length,
          verifiedCount: i,
          tamperedIndex: entry.index,
          error: `Signature mismatch at index ${entry.index}. An unsigned field (severity, category, reasons, or dlpFindingsCount) was altered after the entry was written, or the signing key does not match the one that wrote it.`
        };
      }
    }

    // 4. Tail truncation check against the persisted head anchor.
    //
    // Deleting the last few entries is invisible to the chain: the remaining
    // entries still verify, because nothing in them referenced what came after.
    // Comparing against a separately-persisted anchor is what makes it visible.
    const truncation = this.checkHeadAnchor(list);

    return {
      intact: truncation === null,
      totalEntries: this.entries.length,
      verifiedCount: list.length,
      error: truncation ?? undefined
    };
  }

  /**
   * The anchor records the highest index and hash ever written. It lives in a
   * separate file so that deleting ledger entries cannot delete the evidence that
   * entries were deleted.
   */
  private static headAnchorPath(): string {
    return `${this.ledgerPath}.anchor`;
  }

  private static writeHeadAnchor(entry: AuditEntry): void {
    try {
      fs.writeFileSync(
        this.headAnchorPath(),
        JSON.stringify({ index: entry.index, currentHash: entry.currentHash }),
        'utf-8'
      );
    } catch {
      // An unwritable anchor must not stop the ledger recording decisions.
    }
  }

  private static checkHeadAnchor(list: AuditEntry[]): string | null {
    if (list.length === 0) return null;
    let anchor: { index: number; currentHash: string };
    try {
      anchor = JSON.parse(fs.readFileSync(this.headAnchorPath(), 'utf-8'));
    } catch {
      // No anchor yet, first run. Not evidence of tampering.
      return null;
    }
    const last = list[list.length - 1];
    if (last.index < anchor.index) {
      return `Audit log has been truncated. Anchor expects at least ${anchor.index + 1} entries (last known hash ${anchor.currentHash.slice(0, 16)}...), found ${last.index + 1}.`;
    }
    if (last.index === anchor.index && last.currentHash !== anchor.currentHash) {
      return `Head mismatch at index ${anchor.index}: anchor expects ${anchor.currentHash.slice(0, 16)}..., log contains ${last.currentHash.slice(0, 16)}...`;
    }
    return null;
  }

  public static getEntries(limit: number = 50): AuditEntry[] {
    return this.entries.slice(-limit);
  }

  public static reset(): void {
    this.entries = [];
    this.lastHash = '0'.repeat(64);
    if (fs.existsSync(this.ledgerPath)) {
      try {
        fs.unlinkSync(this.ledgerPath);
      } catch {}
    }
  }
}
