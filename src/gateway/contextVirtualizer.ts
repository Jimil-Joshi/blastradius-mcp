import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { DLPScanner } from '../analyzer/dlpScanner.js';
import { VirtualContextHandle, VirtualizeContextParams } from './types.js';

interface StoredContextEntry {
  content: string;
  handle: VirtualContextHandle;
  expiresAtMs: number;
}

interface ContextMetadata {
  handleId: string;
  label: string;
  createdAt: string;
  expiresAt: string;
  expiresAtMs: number;
  byteSize: number;
}

export class ContextVirtualizer {
  private readonly store: Map<string, StoredContextEntry> = new Map();
  private readonly storageDir: string;

  constructor(customStorageDir?: string) {
    this.storageDir = customStorageDir || path.resolve(process.cwd(), '.blastradius', 'virtual_context');
    this.ensureStorageDir();
  }

  private ensureStorageDir(): void {
    try {
      if (!fs.existsSync(this.storageDir)) {
        fs.mkdirSync(this.storageDir, { recursive: true });
      }
    } catch {
      // Graceful fallback if filesystem access is restricted
    }
  }

  /**
   * Validates handleId to prevent path traversal vulnerabilities.
   */
  private isValidHandleId(handleId: string): boolean {
    return typeof handleId === 'string' && /^ctx_[a-fA-F0-9]{16,64}$/.test(handleId);
  }

  /**
   * Compresses large context payloads (logs, DB dumps, ASTs, diffs) into
   * lightweight virtual handles with token reduction >85%.
   */
  public virtualize(params: VirtualizeContextParams): VirtualContextHandle {
    const rawContent = params.rawContent ?? '';
    const label = params.label || 'context';
    const ttlSeconds = params.retentionTtlSeconds !== undefined ? params.retentionTtlSeconds : 3600;

    const hash = crypto.createHash('sha256').update(rawContent).digest('hex').slice(0, 16);
    const handleId = `ctx_${hash}`;

    const byteSize = Buffer.byteLength(rawContent, 'utf-8');
    const estimatedTokens = Math.max(1, Math.ceil(rawContent.length / 4));

    // Redact any leaked credentials/secrets in preview snippet to avoid echoing secrets
    const rawSnippet = rawContent.slice(0, 500);
    const previewSnippet = DLPScanner.scan(rawSnippet, true).sanitizedContent;

    // Approximate token footprint of the virtual handle header + preview snippet
    const handleTokens = Math.ceil((handleId.length + label.length + previewSnippet.length + 80) / 4);
    const tokensSaved = Math.max(0, estimatedTokens - handleTokens);
    const rawReductionPct = estimatedTokens > 0 ? (tokensSaved / estimatedTokens) * 100 : 0;
    const tokenReductionPercentage = Number(Math.max(0, Math.min(99.9, rawReductionPct)).toFixed(1));

    const now = Date.now();
    const expiresAtMs = now + ttlSeconds * 1000;
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(expiresAtMs).toISOString();

    const handle: VirtualContextHandle = {
      handleId,
      label,
      byteSize,
      originalBytes: byteSize,
      estimatedTokens,
      tokensEstimated: estimatedTokens,
      previewSnippet,
      preview: previewSnippet,
      tokensSaved,
      tokenReductionPercentage,
      retentionTtlSeconds: ttlSeconds,
      createdAt,
      expiresAt
    };

    // Store in-memory
    this.store.set(handleId, {
      content: rawContent,
      handle,
      expiresAtMs
    });

    // Persist to disk (.blastradius/virtual_context/<handleId>.dat and companion .meta.json)
    try {
      this.ensureStorageDir();
      const filePath = path.join(this.storageDir, `${handleId}.dat`);
      const metaPath = path.join(this.storageDir, `${handleId}.meta.json`);
      fs.writeFileSync(filePath, rawContent, 'utf-8');

      const meta: ContextMetadata = {
        handleId,
        label,
        createdAt,
        expiresAt,
        expiresAtMs,
        byteSize
      };
      fs.writeFileSync(metaPath, JSON.stringify(meta), 'utf-8');
    } catch {
      // In-memory fallback
    }

    return handle;
  }

  /**
   * Resolves raw payload content by handleId if not expired and within valid format.
   */
  public resolve(handleId: string): string | null {
    if (!this.isValidHandleId(handleId)) {
      return null;
    }

    const entry = this.store.get(handleId);
    if (entry) {
      if (Date.now() > entry.expiresAtMs) {
        this.store.delete(handleId);
        this.removeFile(handleId);
        return null;
      }
      return entry.content;
    }

    // Attempt retrieval from filesystem with metadata expiration check
    try {
      const metaPath = path.join(this.storageDir, `${handleId}.meta.json`);
      if (fs.existsSync(metaPath)) {
        const meta: ContextMetadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        if (Date.now() > meta.expiresAtMs) {
          this.removeFile(handleId);
          return null;
        }
      }

      const filePath = path.join(this.storageDir, `${handleId}.dat`);
      if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf-8');
      }
    } catch {
      // Ignore read errors
    }

    return null;
  }

  /**
   * Greps / filters lines matching a regex pattern or substring from the virtualized content.
   */
  public query(handleId: string, pattern: string, limit: number = 100): string[] {
    const content = this.resolve(handleId);
    if (!content) {
      return [];
    }

    const lines = content.split(/\r?\n/);
    let matched: string[];
    try {
      const regex = new RegExp(pattern, 'i');
      matched = lines.filter((line) => regex.test(line));
    } catch {
      const lower = pattern.toLowerCase();
      matched = lines.filter((line) => line.toLowerCase().includes(lower));
    }

    return limit > 0 ? matched.slice(0, limit) : matched;
  }

  /**
   * Cleans up expired entries from in-memory cache and local disk storage.
   */
  public cleanupExpired(): number {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [id, entry] of this.store.entries()) {
      if (now >= entry.expiresAtMs) {
        this.store.delete(id);
        this.removeFile(id);
        cleanedCount++;
      }
    }

    // Scan disk storage for expired companion metadata or orphaned files
    try {
      if (fs.existsSync(this.storageDir)) {
        const files = fs.readdirSync(this.storageDir);
        for (const file of files) {
          if (file.endsWith('.meta.json')) {
            const id = file.replace(/\.meta\.json$/, '');
            if (this.isValidHandleId(id)) {
              try {
                const metaPath = path.join(this.storageDir, file);
                const meta: ContextMetadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
                if (now >= meta.expiresAtMs) {
                  this.removeFile(id);
                  cleanedCount++;
                }
              } catch {
                this.removeFile(id);
              }
            }
          } else if (file.endsWith('.dat')) {
            const id = file.replace(/\.dat$/, '');
            const metaPath = path.join(this.storageDir, `${id}.meta.json`);
            if (!fs.existsSync(metaPath)) {
              // Prune orphaned .dat files older than 1 hour
              try {
                const stat = fs.statSync(path.join(this.storageDir, file));
                if (now - stat.mtimeMs > 3600 * 1000) {
                  this.removeFile(id);
                  cleanedCount++;
                }
              } catch {}
            }
          }
        }
      }
    } catch {}

    return cleanedCount;
  }

  /**
   * Clears all stored virtual contexts (for test resets).
   */
  public clear(): void {
    for (const id of this.store.keys()) {
      this.removeFile(id);
    }
    this.store.clear();
  }

  private removeFile(handleId: string): void {
    if (!this.isValidHandleId(handleId)) {
      return;
    }

    try {
      const dataPath = path.join(this.storageDir, `${handleId}.dat`);
      const metaPath = path.join(this.storageDir, `${handleId}.meta.json`);
      if (fs.existsSync(dataPath)) {
        fs.unlinkSync(dataPath);
      }
      if (fs.existsSync(metaPath)) {
        fs.unlinkSync(metaPath);
      }
    } catch {
      // Ignore unlink errors
    }
  }
}

export const contextVirtualizer = new ContextVirtualizer();
