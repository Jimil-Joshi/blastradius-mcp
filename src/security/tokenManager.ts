import * as crypto from 'node:crypto';
import { ApprovalToken, ApprovalTokenPayload } from '../types.js';

/** Approval tokens live for 5 minutes by default and never longer than an hour. */
const MAX_TTL_SECONDS = 3600;

export class TokenManager {
  private static secretKey: string =
    process.env.BLAST_RADIUS_SIGNING_KEY ||
    crypto.randomBytes(32).toString('hex');

  // Consumed token IDs mapped to their expiry so replay can be rejected for the
  // full lifetime of the token. Entries are pruned once the token would have
  // expired anyway, which bounds this map without weakening the check.
  private static consumedTokens: Map<string, number> = new Map();

  /**
   * Set a custom signing key (e.g. for enterprise SSO or distributed nodes)
   */
  public static setSigningKey(key: string): void {
    this.secretKey = key;
  }

  /**
   * Generates a cryptographically signed approval token.
   */
  public static generateToken(
    toolName: string,
    actionFingerprint: string,
    requestedBy: string,
    ttlSeconds: number = 300,
    reason?: string
  ): ApprovalToken {
    const tokenId = `br-tok-${crypto.randomUUID()}`;
    const now = Math.floor(Date.now() / 1000);
    // Clamp the upper bound rather than trust the caller. An approval token that
    // outlives an hour stops being a step-up confirmation and becomes a bearer
    // credential. The lower bound is deliberately not clamped: a zero or
    // negative TTL is honoured as given, which means the token is already dead.
    const ttl = Math.min(MAX_TTL_SECONDS, Math.floor(ttlSeconds));
    const expiresAt = now + ttl;

    const payload: ApprovalTokenPayload = {
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
  public static verifyToken(
    tokenString: string,
    expectedToolName?: string
  ): { valid: boolean; payload?: ApprovalTokenPayload; error?: string } {
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

    let payload: ApprovalTokenPayload;
    try {
      payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf-8'));
    } catch {
      return { valid: false, error: 'Invalid token payload JSON' };
    }

    // Check replay
    if (this.consumedTokens.has(payload.tokenId)) {
      return { valid: false, error: 'Token has already been consumed (replay prevention)' };
    }

    // Check expiration. >= rather than >, so a token minted with a zero or
    // negative TTL is already dead on arrival instead of being honoured for the
    // remainder of the second it expires in.
    const now = Math.floor(Date.now() / 1000);
    if (now >= payload.expiresAt) {
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
   * Called by the PolicyEngine the moment a token authorises an action, which
   * is what makes tokens genuinely single-use rather than merely time-boxed.
   */
  public static consumeToken(tokenId: string, expiresAt?: number): void {
    const expiry = expiresAt ?? Math.floor(Date.now() / 1000) + 300;
    this.consumedTokens.set(tokenId, expiry);
    this.pruneConsumed();
  }

  /**
   * Drops consumed-token entries whose token has already expired. A consumed
   * token can never become valid again, so its record is redundant after expiry.
   */
  public static pruneConsumed(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [tokenId, expiresAt] of this.consumedTokens) {
      if (expiresAt <= now) {
        this.consumedTokens.delete(tokenId);
      }
    }
  }

  /**
   * True when the given token id has already been spent.
   */
  public static isConsumed(tokenId: string): boolean {
    return this.consumedTokens.has(tokenId);
  }

  /**
   * Clears all consumed-token state. Test-only helper.
   */
  public static resetConsumed(): void {
    this.consumedTokens.clear();
  }
}
