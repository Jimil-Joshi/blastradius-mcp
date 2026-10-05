import * as crypto from 'node:crypto';
export class TokenManager {
    static secretKey = process.env.BLAST_RADIUS_SIGNING_KEY ||
        crypto.randomBytes(32).toString('hex');
    // Cache of consumed tokens to prevent replay attacks
    static consumedTokens = new Set();
    /**
     * Set a custom signing key (e.g. for enterprise SSO or distributed nodes)
     */
    static setSigningKey(key) {
        this.secretKey = key;
    }
    /**
     * Generates a cryptographically signed approval token.
     */
    static generateToken(toolName, actionFingerprint, requestedBy, ttlSeconds = 300, reason) {
        const tokenId = `br-tok-${crypto.randomUUID()}`;
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + ttlSeconds;
        const payload = {
            tokenId,
            toolName,
            actionFingerprint,
            requestedBy,
            issuedAt: now,
            expiresAt,
            reason
        };
        const payloadEncoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signature = crypto
            .createHmac('sha256', this.secretKey)
            .update(payloadEncoded)
            .digest('base64url');
        const token = `${payloadEncoded}.${signature}`;
        return { token, payload };
    }
    /**
     * Verifies an approval token against toolName and signature.
     */
    static verifyToken(tokenString, expectedToolName) {
        if (!tokenString || typeof tokenString !== 'string') {
            return { valid: false, error: 'Token string is required' };
        }
        const parts = tokenString.split('.');
        if (parts.length !== 2) {
            return { valid: false, error: 'Malformed token structure' };
        }
        const [payloadEncoded, signature] = parts;
        // Check HMAC
        const expectedSig = crypto
            .createHmac('sha256', this.secretKey)
            .update(payloadEncoded)
            .digest('base64url');
        const sigBuf = Buffer.from(signature);
        const expSigBuf = Buffer.from(expectedSig);
        if (sigBuf.length !== expSigBuf.length || !crypto.timingSafeEqual(sigBuf, expSigBuf)) {
            return { valid: false, error: 'Cryptographic signature mismatch' };
        }
        let payload;
        try {
            payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf-8'));
        }
        catch {
            return { valid: false, error: 'Invalid token payload JSON' };
        }
        // Check replay
        if (this.consumedTokens.has(payload.tokenId)) {
            return { valid: false, error: 'Token has already been consumed (replay prevention)' };
        }
        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (now > payload.expiresAt) {
            return { valid: false, error: 'Token has expired' };
        }
        // Check scope/toolName match
        if (expectedToolName && payload.toolName !== expectedToolName && payload.toolName !== '*') {
            return {
                valid: false,
                error: `Token tool scope mismatch. Expected '${expectedToolName}', token was scoped to '${payload.toolName}'`
            };
        }
        return { valid: true, payload };
    }
    /**
     * Marks a token as consumed so it cannot be re-used.
     */
    static consumeToken(tokenId) {
        this.consumedTokens.add(tokenId);
    }
    /**
     * Clear expired tokens from memory
     */
    static pruneConsumed() {
        // Keep set bounded
        if (this.consumedTokens.size > 10000) {
            this.consumedTokens.clear();
        }
    }
}
