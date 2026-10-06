import test from 'node:test';
import assert from 'node:assert';
import {
  createHackerPersona,
  createConfusedUserPersona,
  createLegacySystemPersona,
  createConcurrencyRacerPersona,
  createDataCorruptorPersona,
  generatePersonas
} from '../../src/swarm/personas/index.js';
import {
  generateHeatmap,
  renderHeatmapAscii,
  renderHeatmapMarkdown
} from '../../src/swarm/heatmapGenerator.js';
import { SwarmNativeEngine } from '../../src/swarm/nativeEngine.js';
import { PersonaFinding } from '../../src/swarm/types.js';

test('HackerPersona - detects SQL injection, auth bypass, IDOR, shell injection, privilege escalation, and token tampering', async () => {
  const hacker = createHackerPersona();
  assert.strictEqual(hacker.type, 'HACKER');
  assert.strictEqual(hacker.focusArea, 'SECURITY');

  // Test SQL Injection
  const sqlDiff = `
  async function getUser(id) {
    return await db.query(\`SELECT * FROM users WHERE id = '\${id}'\`);
  }
  `;
  const sqlFindings = await hacker.evaluate(sqlDiff);
  assert.ok(sqlFindings.some((f: PersonaFinding) => f.attackVector === 'SQL_INJECTION' && f.severity === 'CRITICAL'));
  const sqlFinding = sqlFindings.find((f: PersonaFinding) => f.attackVector === 'SQL_INJECTION');
  assert.ok(sqlFinding?.suggestedTest.includes('SQL'));
  assert.ok(sqlFinding?.reproductionSteps && sqlFinding.reproductionSteps.length > 0);

  // Test Auth Bypass
  const authDiff = `
  app.use((req, res, next) => {
    if (req.headers['x-bypass-auth'] === 'true' || req.query.skipAuth) {
      return next();
    }
    authenticateUser(req, res, next);
  });
  `;
  const authFindings = await hacker.evaluate(authDiff);
  assert.ok(authFindings.some((f: PersonaFinding) => f.attackVector === 'AUTH_BYPASS' && f.severity === 'CRITICAL'));

  // Test IDOR
  const idorDiff = `
  app.get('/api/documents/:docId', async (req, res) => {
    const doc = await Document.findById(req.params.docId);
    return res.json(doc);
  });
  `;
  const idorFindings = await hacker.evaluate(idorDiff);
  assert.ok(idorFindings.some((f: PersonaFinding) => f.attackVector === 'IDOR'));

  // Test Shell Injection
  const shellDiff = `
  const { exec } = require('child_process');
  function runBackup(branch) {
    exec(\`git archive --format=tar \${branch} > backup.tar\`);
  }
  `;
  const shellFindings = await hacker.evaluate(shellDiff);
  assert.ok(shellFindings.some((f: PersonaFinding) => f.attackVector === 'COMMAND_INJECTION' || f.attackVector === 'SHELL_INJECTION'));

  // Test Privilege Escalation
  const privDiff = `
  app.put('/api/users/profile', async (req, res) => {
    const update = { ...req.body };
    await User.update({ id: req.user.id }, update);
  });
  `;
  const privFindings = await hacker.evaluate(privDiff);
  assert.ok(privFindings.some((f: PersonaFinding) => f.attackVector === 'PRIVILEGE_ESCALATION'));

  // Test Token Tampering / Weak Secret
  const tokenDiff = `
  const token = jwt.verify(rawToken, 'secret', { ignoreExpiration: true });
  `;
  const tokenFindings = await hacker.evaluate(tokenDiff);
  assert.ok(tokenFindings.some((f: PersonaFinding) => f.attackVector === 'TOKEN_TAMPERING'));

  // Safe diff
  const safeDiff = `
  const sanitized = Number.parseInt(req.params.id, 10);
  const user = await db.query('SELECT name FROM users WHERE id = $1 AND tenant_id = $2', [sanitized, req.user.tenantId]);
  `;
  const safeFindings = await hacker.evaluate(safeDiff);
  assert.strictEqual(safeFindings.filter((f: PersonaFinding) => f.severity === 'CRITICAL').length, 0);
});

test('ConfusedUserPersona - detects malformed payloads, unhandled undefined access, missing idempotency, and boundary violations', async () => {
  const confused = createConfusedUserPersona();
  assert.strictEqual(confused.type, 'CONFUSED_USER');
  assert.strictEqual(confused.focusArea, 'USABILITY');

  // Test unhandled undefined access
  const undefinedDiff = `
  function extractAddress(req) {
    const street = req.body.customer.billing.address.street;
    return street.toUpperCase();
  }
  `;
  const undefinedFindings = await confused.evaluate(undefinedDiff);
  assert.ok(undefinedFindings.some((f: PersonaFinding) => f.attackVector === 'UNHANDLED_UNDEFINED' || f.attackVector === 'MISSING_OPTIONAL_CHAINING'));

  // Test JSON parse without try/catch
  const parseDiff = `
  function parseConfig(raw) {
    const parsed = JSON.parse(raw);
    return parsed.settings;
  }
  `;
  const parseFindings = await confused.evaluate(parseDiff);
  assert.ok(parseFindings.some((f: PersonaFinding) => f.attackVector === 'UNPROTECTED_JSON_PARSE'));

  // Test non-idempotent critical operation
  const orderDiff = `
  app.post('/api/checkout', async (req, res) => {
    await chargeCreditCard(req.body.userId, req.body.amount);
    await createOrder(req.body);
  });
  `;
  const orderFindings = await confused.evaluate(orderDiff);
  assert.ok(orderFindings.some((f: PersonaFinding) => f.attackVector === 'MISSING_IDEMPOTENCY'));

  // Test boundary violation (e.g. negative balance / unbounded input)
  const boundaryDiff = `
  app.post('/api/transfer', async (req, res) => {
    const { amount, toUser } = req.body;
    account.balance -= amount;
  });
  `;
  const boundaryFindings = await confused.evaluate(boundaryDiff);
  assert.ok(boundaryFindings.some((f: PersonaFinding) => f.attackVector === 'BOUNDARY_VIOLATION'));
});

test('LegacySystemPersona - detects stale headers, deprecated parameters, cache desynchronization, and socket timeouts', async () => {
  const legacy = createLegacySystemPersona();
  assert.strictEqual(legacy.type, 'LEGACY_SYSTEM');
  assert.strictEqual(legacy.focusArea, 'DATA_INTEGRITY');

  // Test unconfigured socket timeout / hanging fetch
  const timeoutDiff = `
  async function fetchPartnerData(endpoint) {
    const response = await fetch('https://legacy-partner.internal' + endpoint);
    return response.json();
  }
  `;
  const timeoutFindings = await legacy.evaluate(timeoutDiff);
  assert.ok(timeoutFindings.some((f: PersonaFinding) => f.attackVector === 'SOCKET_TIMEOUT_HANG'));

  // Test cache desync / missing cache invalidation
  const cacheDiff = `
  async function updateProfile(id, data) {
    await db.users.update(id, data);
    // returns without clearing cache or updating read-replica
  }
  `;
  const cacheFindings = await legacy.evaluate(cacheDiff);
  assert.ok(cacheFindings.some((f: PersonaFinding) => f.attackVector === 'CACHE_DESYNCHRONIZATION'));

  // Test deprecated parameters / breaking legacy compatibility
  const deprecatedDiff = `
  function handleV2Request(req) {
    // Only accept new camelCase parameters, dropping snake_case compatibility
    const userId = req.body.userId;
    if (!userId) throw new Error('userId is required');
  }
  `;
  const deprecatedFindings = await legacy.evaluate(deprecatedDiff);
  assert.ok(deprecatedFindings.some((f: PersonaFinding) => f.attackVector === 'DEPRECATED_SCHEMA_BREAKAGE'));
});

test('ConcurrencyRacerPersona - detects simultaneous token refresh, TOCTOU, and uncoordinated shared state', async () => {
  const racer = createConcurrencyRacerPersona();
  assert.strictEqual(racer.type, 'CONCURRENCY_RACER');
  assert.strictEqual(racer.focusArea, 'CONCURRENCY');

  // Test simultaneous refresh token calls / race condition
  const tokenRaceDiff = `
  async function refreshToken(oldRefreshToken) {
    const session = await findSession(oldRefreshToken);
    if (!session) throw new Error('Invalid token');
    await deleteSession(oldRefreshToken);
    const newTokens = await generateTokens(session.userId);
    await saveSession(newTokens.refreshToken);
    return newTokens;
  }
  `;
  const tokenRaceFindings = await racer.evaluate(tokenRaceDiff);
  assert.ok(tokenRaceFindings.some((f: PersonaFinding) => f.attackVector === 'CONCURRENT_TOKEN_REFRESH' || f.attackVector === 'TOKEN_ROTATION_RACE'));

  // Test TOCTOU (Time of check to time of use)
  const toctouDiff = `
  async function withdraw(userId, amount) {
    const account = await getAccount(userId);
    if (account.balance >= amount) {
      await deductBalance(userId, amount);
      await sendFunds(userId, amount);
    }
  }
  `;
  const toctouFindings = await racer.evaluate(toctouDiff);
  assert.ok(toctouFindings.some((f: PersonaFinding) => f.attackVector === 'TOCTOU_RACE_CONDITION'));

  // Test uncoordinated mutable shared state in module scope
  const sharedStateDiff = `
  let activeConnectionCount = 0;
  async function handleConnection(req) {
    activeConnectionCount++;
    await doProcessing();
    activeConnectionCount--;
  }
  `;
  const sharedStateFindings = await racer.evaluate(sharedStateDiff);
  assert.ok(sharedStateFindings.some((f: PersonaFinding) => f.attackVector === 'UNSYNCHRONIZED_SHARED_STATE'));
});

test('DataCorruptorPersona - detects null byte poisoning, type confusion, and numeric singularities', async () => {
  const corruptor = createDataCorruptorPersona();
  assert.strictEqual(corruptor.type, 'DATA_CORRUPTOR');
  assert.strictEqual(corruptor.focusArea, 'DATA_INTEGRITY');

  // Test poison null byte injection
  const nullByteDiff = `
  function loadFile(req, res) {
    const filePath = path.join('/var/data', req.params.filename);
    const content = fs.readFileSync(filePath, 'utf8');
    return res.send(content);
  }
  `;
  const nullByteFindings = await corruptor.evaluate(nullByteDiff);
  assert.ok(nullByteFindings.some((f: PersonaFinding) => f.attackVector === 'NULL_BYTE_POISONING'));

  // Test type confusion / NoSQL object injection
  const typeConfusionDiff = `
  async function findAccount(req, res) {
    const account = await Account.findOne({ username: req.body.username });
    return res.json(account);
  }
  `;
  const typeFindings = await corruptor.evaluate(typeConfusionDiff);
  assert.ok(typeFindings.some((f: PersonaFinding) => f.attackVector === 'TYPE_CONFUSION_INJECTION'));

  // Test numeric singularity / unchecked NaN parsing
  const nanDiff = `
  function parseLimit(req) {
    const limit = parseInt(req.query.limit);
    return limit * 10;
  }
  `;
  const nanFindings = await corruptor.evaluate(nanDiff);
  assert.ok(nanFindings.some((f: PersonaFinding) => f.attackVector === 'NUMERIC_SINGULARITY_NAN'));
});

test('False positive resilience - anchored property access, scoped boundary checks, and compound isolation', async () => {
  const confused = createConfusedUserPersona();

  // process.env.NODE_ENV.toLowerCase() should NOT be flagged as unhandled undefined
  const benignDeep = `
  function getEnv() {
    return process.env.NODE_ENV.toLowerCase();
  }
  `;
  const deepFindings = await confused.evaluate(benignDeep);
  assert.strictEqual(deepFindings.filter((f: PersonaFinding) => f.attackVector === 'UNHANDLED_UNDEFINED').length, 0);

  // fileTransfer should NOT trigger boundary violation
  const benignTransfer = `
  function fileTransfer(filename, targetFolder) {
    return path.join(targetFolder, filename);
  }
  `;
  const boundaryFindings = await confused.evaluate(benignTransfer);
  assert.strictEqual(boundaryFindings.filter((f: PersonaFinding) => f.attackVector === 'BOUNDARY_VIOLATION').length, 0);

  // Token refresh race alone should NOT trigger COMPOUND_AUTH_RACE
  const engine = new SwarmNativeEngine();
  const tokenOnlyDiff = `
  async function refresh(oldToken) {
    const s = await db.sessions.find(oldToken);
    await db.sessions.delete(oldToken);
    const n = generateToken();
    await db.sessions.save(n);
    return n;
  }
  `;
  const simRes = await engine.simulate({ targetDiffOrCommand: tokenOnlyDiff, agentCount: 25 });
  assert.strictEqual(simRes.criticalFindings.filter((f: PersonaFinding) => f.attackVector === 'COMPOUND_AUTH_RACE').length, 0);
});

test('generatePersonas - generates requested count and handles focus areas', () => {
  const personas25 = generatePersonas(25);
  assert.strictEqual(personas25.length, 25);

  const types = new Set(personas25.map(p => p.type));
  assert.ok(types.has('HACKER'));
  assert.ok(types.has('CONFUSED_USER'));
  assert.ok(types.has('LEGACY_SYSTEM'));
  assert.ok(types.has('CONCURRENCY_RACER'));
  assert.ok(types.has('DATA_CORRUPTOR'));

  const personas50 = generatePersonas(50);
  assert.strictEqual(personas50.length, 50);

  // Filtered by focus area
  const securityOnly = generatePersonas(10, ['SECURITY']);
  assert.strictEqual(securityOnly.length, 10);
  assert.ok(securityOnly.every(p => p.focusArea === 'SECURITY'));

  const concurrencyOnly = generatePersonas(10, ['CONCURRENCY']);
  assert.strictEqual(concurrencyOnly.length, 10);
  assert.ok(concurrencyOnly.every(p => p.focusArea === 'CONCURRENCY'));
});

test('HeatmapGenerator - generates matrix and renders clean ASCII, Markdown, and JSON', () => {
  const findings: PersonaFinding[] = [
    {
      personaType: 'HACKER',
      attackVector: 'SQL_INJECTION',
      description: 'Raw SQL string concatenation exposes UserEntity table to exfiltration',
      suggestedTest: 'it("should reject malicious SQL string in id parameter")',
      severity: 'CRITICAL',
      affectedEntity: 'Database'
    },
    {
      personaType: 'HACKER',
      attackVector: 'AUTH_BYPASS',
      description: 'x-bypass-auth header circumvents session middleware',
      suggestedTest: 'it("should not bypass auth with x-bypass-auth header")',
      severity: 'CRITICAL',
      affectedEntity: 'Auth'
    },
    {
      personaType: 'CONCURRENCY_RACER',
      attackVector: 'CONCURRENT_TOKEN_REFRESH',
      description: 'Parallel refresh requests cause race condition in token rotation',
      suggestedTest: 'it("should lock refresh token rotation during concurrent exchange")',
      severity: 'HIGH',
      affectedEntity: 'APIs'
    }
  ];

  const matrix = generateHeatmap('sample diff code', findings, 85);

  // Verify dimensions and components
  assert.ok(matrix.dimensions.components.includes('Auth'));
  assert.ok(matrix.dimensions.components.includes('Database'));
  assert.ok(matrix.dimensions.components.includes('Storage'));
  assert.ok(matrix.dimensions.components.includes('Network'));
  assert.ok(matrix.dimensions.components.includes('Filesystem'));
  assert.ok(matrix.dimensions.components.includes('APIs'));

  assert.strictEqual(matrix.overallScore, 85);

  // Verify cell values
  const authCell = matrix.cells.find(c => c.component === 'Auth');
  assert.ok(authCell);
  assert.strictEqual(authCell?.risk, 'CRITICAL');

  const dbCell = matrix.cells.find(c => c.component === 'Database');
  assert.ok(dbCell);
  assert.strictEqual(dbCell?.risk, 'CRITICAL');

  // Verify user classes and data sensitivity
  assert.ok(matrix.userClasses && matrix.userClasses.length > 0);
  assert.ok(matrix.dataSensitivity && matrix.dataSensitivity.length > 0);
  assert.ok(matrix.containmentFeasibility);

  // Verify ASCII rendering
  const ascii = renderHeatmapAscii(matrix);
  assert.ok(typeof ascii === 'string');
  assert.ok(ascii.includes('BLASTRADIUS BLAST HEATMAP') || ascii.includes('HEATMAP'));
  assert.ok(ascii.includes('Auth'));
  assert.ok(ascii.includes('CRITICAL'));
  assert.ok(ascii.includes('85'));

  // Verify Markdown rendering
  const md = renderHeatmapMarkdown(matrix);
  assert.ok(typeof md === 'string');
  assert.ok(md.includes('| Component |'));
  assert.ok(md.includes('[CRITICAL]'));
  assert.ok(md.includes('Auth'));

  // Verify JSON serialization
  const jsonStr = JSON.stringify(matrix);
  const parsed = JSON.parse(jsonStr);
  assert.strictEqual(parsed.overallScore, 85);
  assert.strictEqual(parsed.cells.length, matrix.cells.length);
});

test('SwarmNativeEngine - runs 25-agent and 50-agent simulation runs in sub-3000ms', async () => {
  const engine = new SwarmNativeEngine();

  // 25-agent simulation run
  const start25 = Date.now();
  const res25 = await engine.simulate({
    targetDiffOrCommand: `
    app.post('/api/token/refresh', async (req, res) => {
      const { refreshToken } = req.body;
      const session = await db.sessions.find(refreshToken);
      if (!session) return res.status(401).send();
      await db.sessions.delete(refreshToken);
      const newToken = generateNewToken();
      await db.sessions.save(newToken);
      return res.json({ token: newToken });
    });
    `,
    agentCount: 25,
    intensity: 'FAST'
  });
  const elapsed25 = Date.now() - start25;

  assert.ok(elapsed25 < 3000, `25-agent run took ${elapsed25}ms which exceeds 3000ms`);
  assert.strictEqual(res25.personasSimulated, 25);
  assert.ok(res25.simulationId.length > 0);
  assert.ok(res25.criticalFindings.length > 0);
  assert.ok(res25.heatmapAscii.length > 0);
  assert.ok(typeof res25.prRiskScore === 'number');

  // 50-agent simulation run
  const start50 = Date.now();
  const res50 = await engine.simulate({
    targetDiffOrCommand: `
    function queryProduct(name) {
      return db.query("SELECT * FROM products WHERE name = '" + name + "'");
    }
    `,
    agentCount: 50,
    intensity: 'FAST'
  });
  const elapsed50 = Date.now() - start50;

  assert.ok(elapsed50 < 3000, `50-agent run took ${elapsed50}ms which exceeds 3000ms`);
  assert.strictEqual(res50.personasSimulated, 50);
});

test('SwarmNativeEngine - detects race conditions in concurrent token refresh diffs', async () => {
  const engine = new SwarmNativeEngine();
  const tokenRaceDiff = `
  export async function handleTokenRefresh(req, res) {
    const token = req.headers['x-refresh-token'];
    const current = await tokenStore.get(token);
    if (!current) throw new Error('Invalid token');
    await tokenStore.revoke(token);
    const nextToken = crypto.randomUUID();
    await tokenStore.set(nextToken, current.userId);
    res.json({ token: nextToken });
  }
  `;

  const result = await engine.simulate({
    targetDiffOrCommand: tokenRaceDiff,
    contextDescription: 'Token refresh endpoint without transactional mutex',
    agentCount: 25
  });

  const raceFinding = result.criticalFindings.find(
    (f: PersonaFinding) => f.attackVector === 'CONCURRENT_TOKEN_REFRESH' || f.attackVector === 'TOKEN_ROTATION_RACE' || f.attackVector === 'TOCTOU_RACE_CONDITION'
  );
  assert.ok(raceFinding, 'Expected engine to find token race condition');
  assert.ok(raceFinding?.suggestedTest, 'Expected suggested test for race condition');
  assert.ok(raceFinding?.reproductionSteps && raceFinding.reproductionSteps.length > 0);
  assert.ok(result.prRiskScore >= 30, 'Risk score should be elevated for race condition');
});

test('SwarmNativeEngine - detects SQL injection and auth bypass with reproduction steps and assertions', async () => {
  const engine = new SwarmNativeEngine();
  const dangerousDiff = `
  router.get('/admin/users', async (req, res) => {
    if (req.query.skipAuth === '1') {
      const q = "SELECT * FROM users WHERE role = '" + req.query.role + "'";
      const results = await rawDb.query(q);
      return res.json(results);
    }
  });
  `;

  const result = await engine.simulate({
    targetDiffOrCommand: dangerousDiff,
    agentCount: 25
  });

  assert.strictEqual(result.verdict, 'BLOCK');
  assert.ok(result.prRiskScore >= 70, `Expected score >= 70 for critical vulnerabilities, got ${result.prRiskScore}`);

  const sqlFinding = result.criticalFindings.find((f: PersonaFinding) => f.attackVector === 'SQL_INJECTION');
  assert.ok(sqlFinding, 'Expected SQL injection finding');
  assert.strictEqual(sqlFinding?.severity, 'CRITICAL');
  assert.ok(sqlFinding?.suggestedTest.includes('SQL') || sqlFinding?.suggestedTest.includes('reject'));

  const authFinding = result.criticalFindings.find((f: PersonaFinding) => f.attackVector === 'AUTH_BYPASS');
  assert.ok(authFinding, 'Expected auth bypass finding');
  assert.strictEqual(authFinding?.severity, 'CRITICAL');
});

test('SwarmNativeEngine - computes PR Risk Score and respects verdict thresholds (SAFE < 30, WARN 30-70, BLOCK >= 70)', async () => {
  const engine = new SwarmNativeEngine();

  // 1. Benign/safe diff -> SAFE (< 30)
  const safeDiff = `
  // Safe helper function with input validation
  export function formatTimestamp(date: Date): string {
    if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
      throw new TypeError('Invalid date object provided');
    }
    return date.toISOString();
  }
  `;
  const safeResult = await engine.simulate({
    targetDiffOrCommand: safeDiff,
    agentCount: 25
  });
  assert.ok(safeResult.prRiskScore < 30, `Expected score < 30 for safe diff, got ${safeResult.prRiskScore}`);
  assert.strictEqual(safeResult.verdict, 'SAFE');

  // 2. Moderate risk (e.g., missing timeout or unhandled undefined) -> WARN (30 - 69)
  const warnDiff = `
  export async function getRemoteMetrics(serviceUrl: string) {
    // Missing timeout, potential slow network socket hang
    const res = await fetch(serviceUrl);
    return res.json();
  }
  `;
  const warnResult = await engine.simulate({
    targetDiffOrCommand: warnDiff,
    agentCount: 25
  });
  assert.ok(
    warnResult.prRiskScore >= 30 && warnResult.prRiskScore < 70,
    `Expected score in [30, 69] for moderate diff, got ${warnResult.prRiskScore}`
  );
  assert.strictEqual(warnResult.verdict, 'WARN');

  // 3. High risk (Auth bypass or SQL injection) -> BLOCK (>= 70)
  const blockDiff = `
  export async function deleteAccount(req, res) {
    if (req.headers['x-admin-override']) {
      await db.execute(\`DELETE FROM accounts WHERE id = '\${req.params.id}'\`);
      return res.send('OK');
    }
  }
  `;
  const blockResult = await engine.simulate({
    targetDiffOrCommand: blockDiff,
    agentCount: 25
  });
  assert.ok(blockResult.prRiskScore >= 70, `Expected score >= 70, got ${blockResult.prRiskScore}`);
  assert.strictEqual(blockResult.verdict, 'BLOCK');
});

