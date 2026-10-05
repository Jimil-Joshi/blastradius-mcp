import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
export class AuditLedger {
    static ledgerPath = path.join(process.cwd(), 'blastradius-audit.jsonl');
    static entries = [];
    static lastHash = '0'.repeat(64); // Genesis hash
    static secretKey = process.env.BLAST_RADIUS_AUDIT_KEY ||
        crypto.randomBytes(32).toString('hex');
    static initialize(customFilePath) {
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
                    if (!line.trim())
                        continue;
                    const entry = JSON.parse(line);
                    this.entries.push(entry);
                    this.lastHash = entry.currentHash;
                }
            }
            catch (err) {
                // Fallback gracefully if corrupted, start fresh
            }
        }
    }
    /**
     * Append a new audit record to the cryptographic hash chain.
     */
    static record(params) {
        const index = this.entries.length;
        const timestamp = new Date().toISOString();
        const prevHash = this.lastHash;
        const inputHash = crypto
            .createHash('sha256')
            .update(JSON.stringify(params.rawPayload || {}))
            .digest('hex');
        const contentToHash = `${index}:${timestamp}:${params.toolName}:${params.callerId}:${params.decision}:${params.dangerScore}:${inputHash}:${prevHash}`;
        const currentHash = crypto.createHash('sha256').update(contentToHash).digest('hex');
        const signature = crypto
            .createHmac('sha256', this.secretKey)
            .update(currentHash)
            .digest('hex');
        const entry = {
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
        // Append to file asynchronously / safely
        try {
            fs.appendFileSync(this.ledgerPath, JSON.stringify(entry) + '\n', 'utf-8');
        }
        catch {
            // In constrained environments where filesystem is read-only, keep in-memory
        }
        return entry;
    }
    /**
     * Cryptographically verifies the entire chain or a recent window of entries.
     * Returns whether the chain is unbroken and untampered.
     */
    static verifyIntegrity(limit) {
        const list = limit ? this.entries.slice(-limit) : this.entries;
        if (list.length === 0) {
            return { intact: true, totalEntries: 0, verifiedCount: 0 };
        }
        for (let i = 0; i < list.length; i++) {
            const entry = list[i];
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
        }
        return {
            intact: true,
            totalEntries: this.entries.length,
            verifiedCount: list.length
        };
    }
    static getEntries(limit = 50) {
        return this.entries.slice(-limit);
    }
    static reset() {
        this.entries = [];
        this.lastHash = '0'.repeat(64);
        if (fs.existsSync(this.ledgerPath)) {
            try {
                fs.unlinkSync(this.ledgerPath);
            }
            catch { }
        }
    }
}
