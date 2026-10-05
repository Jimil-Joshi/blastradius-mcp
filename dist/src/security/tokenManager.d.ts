import { ApprovalToken, ApprovalTokenPayload } from '../types.js';
export declare class TokenManager {
    private static secretKey;
    private static consumedTokens;
    /**
     * Set a custom signing key (e.g. for enterprise SSO or distributed nodes)
     */
    static setSigningKey(key: string): void;
    /**
     * Generates a cryptographically signed approval token.
     */
    static generateToken(toolName: string, actionFingerprint: string, requestedBy: string, ttlSeconds?: number, reason?: string): ApprovalToken;
    /**
     * Verifies an approval token against toolName and signature.
     */
    static verifyToken(tokenString: string, expectedToolName?: string): {
        valid: boolean;
        payload?: ApprovalTokenPayload;
        error?: string;
    };
    /**
     * Marks a token as consumed so it cannot be re-used.
     */
    static consumeToken(tokenId: string): void;
    /**
     * Clear expired tokens from memory
     */
    static pruneConsumed(): void;
}
