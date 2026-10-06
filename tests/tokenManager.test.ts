import test, { afterEach, beforeEach } from 'node:test';
import assert from 'node:assert';
import { TokenManager } from '../src/security/tokenManager.js';
import { ApprovalTokenPayload } from '../src/types.js';

const TOOL_NAME = 'execute_shell';
const SIGNING_KEY = 'unit-test-primary-signing-key';
const DEFAULT_TTL_SECONDS = 300;

function decodePayload(token: string): ApprovalTokenPayload {
  const [payloadEncoded] = token.split('.');
  return JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf-8')) as ApprovalTokenPayload;
}

function encodePayload(payload: ApprovalTokenPayload): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

beforeEach(() => {
  TokenManager.setSigningKey(SIGNING_KEY);
  TokenManager.resetConsumed();
});

afterEach(() => {
  TokenManager.setSigningKey(SIGNING_KEY);
  TokenManager.resetConsumed();
});

test('TokenManager - Issues a verifiable token carrying the expected payload fields', () => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const approval = TokenManager.generateToken(
    TOOL_NAME,
    'sha256:action-fingerprint',
    'supervisor@example.com',
    DEFAULT_TTL_SECONDS,
    'Approved during change window'
  );

  assert.strictEqual(approval.payload.toolName, TOOL_NAME);
  assert.strictEqual(approval.payload.actionFingerprint, 'sha256:action-fingerprint');
  assert.strictEqual(approval.payload.requestedBy, 'supervisor@example.com');
  assert.strictEqual(approval.payload.reason, 'Approved during change window');
  assert.ok(approval.payload.tokenId.startsWith('br-tok-'));
  assert.ok(approval.payload.issuedAt >= issuedAt);
  assert.strictEqual(
    approval.payload.expiresAt,
    approval.payload.issuedAt + DEFAULT_TTL_SECONDS
  );

  const verification = TokenManager.verifyToken(approval.token, TOOL_NAME);
  assert.strictEqual(verification.valid, true);
  assert.strictEqual(verification.error, undefined);
  assert.deepStrictEqual(verification.payload, approval.payload);
});

test('TokenManager - Rejects a token signed with a different key', () => {
  const approval = TokenManager.generateToken(TOOL_NAME, 'fingerprint', 'supervisor');
  assert.strictEqual(TokenManager.verifyToken(approval.token, TOOL_NAME).valid, true);

  TokenManager.setSigningKey('a-different-signing-key');
  const result = TokenManager.verifyToken(approval.token, TOOL_NAME);

  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'Cryptographic signature mismatch');
  assert.strictEqual(result.payload, undefined);

  TokenManager.setSigningKey(SIGNING_KEY);
  assert.strictEqual(TokenManager.verifyToken(approval.token, TOOL_NAME).valid, true);
});

test('TokenManager - Rejects a token whose payload was tampered with', () => {
  const approval = TokenManager.generateToken(TOOL_NAME, 'fingerprint', 'supervisor');
  const signature = approval.token.split('.')[1];

  const payload = decodePayload(approval.token);
  payload.requestedBy = 'attacker';
  const tampered = `${encodePayload(payload)}.${signature}`;

  assert.notStrictEqual(tampered, approval.token);
  const result = TokenManager.verifyToken(tampered, TOOL_NAME);

  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'Cryptographic signature mismatch');
  assert.strictEqual(TokenManager.verifyToken(approval.token, TOOL_NAME).valid, true);
});

test('TokenManager - Rejects a token whose lifetime has already elapsed', () => {
  const expired = TokenManager.generateToken(TOOL_NAME, 'fingerprint', 'supervisor', -60);
  assert.ok(expired.payload.expiresAt < Math.floor(Date.now() / 1000));

  const result = TokenManager.verifyToken(expired.token, TOOL_NAME);

  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'Token has expired');
  assert.strictEqual(TokenManager.isConsumed(expired.payload.tokenId), false);
});

test('TokenManager - Rejects a consumed token on subsequent verification', () => {
  const approval = TokenManager.generateToken(TOOL_NAME, 'fingerprint', 'supervisor');
  assert.strictEqual(TokenManager.isConsumed(approval.payload.tokenId), false);

  TokenManager.consumeToken(approval.payload.tokenId);
  assert.strictEqual(TokenManager.isConsumed(approval.payload.tokenId), true);

  const result = TokenManager.verifyToken(approval.token, TOOL_NAME);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'Token has already been consumed (replay prevention)');
});

test('TokenManager - Rejects a token scoped to a different tool', () => {
  const approval = TokenManager.generateToken('deploy_production', 'fingerprint', 'supervisor');

  const mismatch = TokenManager.verifyToken(approval.token, 'execute_shell');
  assert.strictEqual(mismatch.valid, false);
  assert.ok(mismatch.error?.includes('Token tool scope mismatch'));
  assert.ok(mismatch.error?.includes("'execute_shell'"));

  assert.strictEqual(TokenManager.verifyToken(approval.token, 'deploy_production').valid, true);
  assert.strictEqual(TokenManager.verifyToken(approval.token).valid, true);
});

test('TokenManager - Accepts a wildcard-scoped token for any tool', () => {
  const approval = TokenManager.generateToken('*', 'fingerprint', 'supervisor');

  const verification = TokenManager.verifyToken(approval.token, 'enforce_policy');

  assert.strictEqual(verification.valid, true);
  assert.strictEqual(verification.payload?.toolName, '*');
});

test('TokenManager - Prunes consumed records only once their expiry has passed', () => {
  const staleId = 'br-tok-stale';
  const liveId = 'br-tok-live';
  const alreadyExpired = Math.floor(Date.now() / 1000) - 60;

  TokenManager.consumeToken(staleId, alreadyExpired);
  assert.strictEqual(TokenManager.isConsumed(staleId), false);

  TokenManager.consumeToken(liveId, Math.floor(Date.now() / 1000) + 300);
  assert.strictEqual(TokenManager.isConsumed(liveId), true);

  TokenManager.pruneConsumed();
  assert.strictEqual(TokenManager.isConsumed(liveId), true);

  TokenManager.resetConsumed();
  assert.strictEqual(TokenManager.isConsumed(liveId), false);
});

test('TokenManager - Rejects a malformed token string', () => {
  const noSeparator = TokenManager.verifyToken('not-a-token', TOOL_NAME);
  assert.strictEqual(noSeparator.valid, false);
  assert.strictEqual(noSeparator.error, 'Malformed token structure');

  const empty = TokenManager.verifyToken('', TOOL_NAME);
  assert.strictEqual(empty.valid, false);
  assert.strictEqual(empty.error, 'Token string is required');
});