import test from 'node:test';
import assert from 'node:assert';
import {
  SemanticRouter,
  semanticRouter,
  ContextVirtualizer,
  contextVirtualizer,
  SandboxExecutor,
  sandboxExecutor,
  RegisteredToolSchema
} from '../../src/gateway/index.js';

test('SemanticRouter - seeds default MCP tools catalog', () => {
  const router = new SemanticRouter();
  const tools = router.listTools();
  assert.ok(tools.length >= 7, `Expected at least 7 default tools, got ${tools.length}`);

  const toolNames = tools.map((t: RegisteredToolSchema) => t.name);
  assert.ok(toolNames.includes('postgres-query'));
  assert.ok(toolNames.includes('github-create-pr'));
  assert.ok(toolNames.includes('kubernetes-deploy'));
  assert.ok(toolNames.includes('git-commit'));
  assert.ok(toolNames.includes('filesystem-read'));
  assert.ok(toolNames.includes('slack-notify'));
  assert.ok(toolNames.includes('aws-s3-upload'));
});

test('SemanticRouter - registers custom tool and lists it', () => {
  const router = new SemanticRouter();
  const initialCount = router.listTools().length;

  const customTool: RegisteredToolSchema = {
    name: 'custom-metric-logger',
    description: 'Log custom observability metric counter or histogram',
    serverName: 'monitoring-mcp',
    inputSchema: {
      type: 'object',
      properties: {
        metricName: { type: 'string' },
        value: { type: 'number' }
      },
      required: ['metricName', 'value']
    },
    tags: ['monitoring', 'metrics', 'telemetry'],
    keywords: ['metric', 'counter', 'histogram', 'gauge', 'stats'],
    examples: ['log counter metric', 'record metric value']
  };

  router.registerTool(customTool);
  const updatedTools = router.listTools();
  assert.strictEqual(updatedTools.length, initialCount + 1);

  const found = updatedTools.find((t: RegisteredToolSchema) => t.name === 'custom-metric-logger');
  assert.ok(found);
  assert.strictEqual(found?.serverName, 'monitoring-mcp');
});

test('SemanticRouter - routes intent to best matching tool with high confidence', async () => {
  const router = new SemanticRouter();

  const res1 = await router.route({ intent: 'query active user sessions in postgres' });
  assert.strictEqual(res1.matchedTool, 'postgres-query');
  assert.ok(res1.confidence >= 0.7, `Expected confidence >= 0.7, got ${res1.confidence}`);
  assert.strictEqual(res1.serverName, 'postgres');
  assert.ok(res1.schema);

  const res2 = await router.route({ intent: 'create pull request for feature branch' });
  assert.strictEqual(res2.matchedTool, 'github-create-pr');
  assert.ok(res2.confidence >= 0.7);

  const res3 = await router.route({ intent: 'deploy commit to staging cluster' });
  assert.strictEqual(res3.matchedTool, 'kubernetes-deploy');
  assert.ok(res3.confidence >= 0.7);

  const res4 = await router.route({ intent: 'upload build artifacts to s3 bucket' });
  assert.strictEqual(res4.matchedTool, 'aws-s3-upload');
  assert.ok(res4.confidence >= 0.7);
});

test('SemanticRouter - respects candidateServer filter', async () => {
  const router = new SemanticRouter();

  // "commit" could match git-commit, but candidateServer: "github" should not match git-commit
  const res = await router.route({
    intent: 'create review pr and commit',
    candidateServer: 'github'
  });
  assert.strictEqual(res.matchedTool, 'github-create-pr');
  assert.strictEqual(res.serverName, 'github');

  // If candidateServer does not have any matching tool, confidence should be 0
  const noMatch = await router.route({
    intent: 'query postgres database',
    candidateServer: 'unknown-server'
  });
  assert.strictEqual(noMatch.confidence, 0);
  assert.strictEqual(noMatch.matchedTool, '');
});

test('SemanticRouter - JIT schema fetch and token savings (>85%)', async () => {
  const router = new SemanticRouter();

  const res = await router.route({ intent: 'read package.json from disk' });
  assert.strictEqual(res.matchedTool, 'filesystem-read');
  assert.ok(res.schema);
  assert.strictEqual((res.schema as RegisteredToolSchema).name, 'filesystem-read');

  // Verify token savings are calculated and exceed 85%
  assert.ok(typeof res.tokenSavingsEstimated === 'number');
  assert.ok(res.tokenSavingsEstimated > 85, `Expected tokenSavingsEstimated > 85, got ${res.tokenSavingsEstimated}`);
  assert.ok(typeof res.tokensSaved === 'number');
  assert.ok(res.tokensSaved > 500, `Expected tokensSaved > 500, got ${res.tokensSaved}`);
});

test('SemanticRouter - executes immediately when executeImmediately is true', async () => {
  const router = new SemanticRouter();
  let executedArgs: any = null;

  router.registerTool({
    name: 'safe-math-calculator',
    description: 'Add two numbers safely',
    serverName: 'calculator',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } }
    },
    tags: ['calculator', 'math'],
    keywords: ['add', 'calculate', 'sum'],
    examples: ['add numbers', 'calculate sum'],
    handler: (args: Record<string, any>) => {
      executedArgs = args;
      return { sum: args.a + args.b };
    }
  });

  const res = await router.route({
    intent: 'add numbers together',
    executeImmediately: true,
    toolArguments: { a: 21, b: 21 }
  });

  assert.strictEqual(res.matchedTool, 'safe-math-calculator');
  assert.strictEqual(res.executed, true);
  assert.deepStrictEqual(res.executionResult, { sum: 42 });
  assert.deepStrictEqual(executedArgs, { a: 21, b: 21 });
});

test('SemanticRouter - blocks execution immediately if argument contains dangerous commands', async () => {
  const router = new SemanticRouter();

  const res = await router.route({
    intent: 'run bash script or command',
    executeImmediately: true,
    toolArguments: { command: 'rm -rf /' }
  });

  assert.strictEqual(res.executed, false);
  assert.ok(res.reasoning?.includes('blocked') || res.reasoning?.includes('violation'));
  assert.strictEqual(res.executionResult?.securityVerdict, 'BLOCK');
});

test('ContextVirtualizer - virtualizes 100KB+ text and generates handle with >85% token reduction', () => {
  const cv = new ContextVirtualizer();

  // Create 120KB payload
  const line = '2026-10-06T14:30:00Z [INFO] Service worker heartbeat processed event payload ID 98234.\n';
  const repeatCount = Math.ceil(120000 / line.length);
  const rawContent = line.repeat(repeatCount);
  assert.ok(Buffer.byteLength(rawContent, 'utf-8') >= 120000);

  const handle = cv.virtualize({
    rawContent,
    label: 'worker-telemetry-logs',
    retentionTtlSeconds: 1800
  });

  assert.ok(handle.handleId.startsWith('ctx_'));
  assert.strictEqual(handle.label, 'worker-telemetry-logs');
  assert.ok(handle.byteSize! >= 120000);
  assert.ok(handle.previewSnippet);
  assert.strictEqual(handle.previewSnippet?.length, 500);
  assert.strictEqual(handle.previewSnippet, rawContent.slice(0, 500));
  assert.ok(handle.tokenReductionPercentage! > 85, `Expected tokenReductionPercentage > 85, got ${handle.tokenReductionPercentage}`);
  assert.ok(handle.tokensSaved! > 1000);
  assert.ok(new Date(handle.expiresAt).getTime() > Date.now());
});

test('ContextVirtualizer - resolves content by handleId', () => {
  const cv = new ContextVirtualizer();
  const testPayload = 'DATABASE DUMP SCHEMA: TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));\n' + 'ENTRY\n'.repeat(500);

  const handle = cv.virtualize({
    rawContent: testPayload,
    label: 'db-dump'
  });

  const resolved = cv.resolve(handle.handleId);
  assert.strictEqual(resolved, testPayload);

  const notFound = cv.resolve('ctx_nonexistent_id');
  assert.strictEqual(notFound, null);
});

test('ContextVirtualizer - query filters matching lines by pattern', () => {
  const cv = new ContextVirtualizer();
  const logs = [
    '2026-10-06 10:00:00 [INFO] Server started on port 8080',
    '2026-10-06 10:00:05 [WARN] Slow database connection detected in pool',
    '2026-10-06 10:00:10 [FATAL ERROR] Null pointer dereference in auth controller',
    '2026-10-06 10:00:15 [INFO] Health check returned 200 OK',
    '2026-10-06 10:00:20 [FATAL ERROR] Out of memory allocating buffer'
  ].join('\n');

  const handle = cv.virtualize({
    rawContent: logs,
    label: 'server-logs'
  });

  const errors = cv.query(handle.handleId, 'FATAL ERROR');
  assert.strictEqual(errors.length, 2);
  assert.ok(errors[0].includes('Null pointer dereference'));
  assert.ok(errors[1].includes('Out of memory'));

  const warns = cv.query(handle.handleId, 'WARN');
  assert.strictEqual(warns.length, 1);
  assert.ok(warns[0].includes('Slow database connection'));

  const empty = cv.query(handle.handleId, 'NONEXISTENT_STRING_PATTERN');
  assert.strictEqual(empty.length, 0);
});

test('ContextVirtualizer - cleanupExpired cleans up expired records', async () => {
  const cv = new ContextVirtualizer();

  // Create handle with 0 TTL (already expired or expires immediately)
  const handle = cv.virtualize({
    rawContent: 'temporary transient secret context',
    label: 'transient',
    retentionTtlSeconds: 0
  });

  // Artificial small delay to ensure expired timestamp has elapsed
  await new Promise((r) => setTimeout(r, 20));

  const cleaned = cv.cleanupExpired();
  assert.ok(cleaned >= 1, `Expected at least 1 cleaned handle, got ${cleaned}`);

  const resolved = cv.resolve(handle.handleId);
  assert.strictEqual(resolved, null);
});

test('SandboxExecutor - allows safe operations and executes simulated or handler', async () => {
  const executor = new SandboxExecutor();

  const tool: RegisteredToolSchema = {
    name: 'filesystem-read',
    description: 'Read file contents',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } }
  };

  const safeResult = await executor.execute(tool, { path: 'README.md' });
  assert.strictEqual(safeResult.success, true);
  assert.strictEqual(safeResult.securityVerdict, 'ALLOW');
  assert.ok(safeResult.result);
  assert.strictEqual(safeResult.result.tool, 'filesystem-read');
});

test('SandboxExecutor - blocks destructive shell commands (rm -rf /)', async () => {
  const executor = new SandboxExecutor();

  const tool: RegisteredToolSchema = {
    name: 'bash-exec',
    description: 'Execute bash commands',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } } }
  };

  const dangerousResult = await executor.execute(tool, { command: 'rm -rf /' });
  assert.strictEqual(dangerousResult.success, false);
  assert.strictEqual(dangerousResult.securityVerdict, 'BLOCK');
  assert.ok(dangerousResult.reason?.toLowerCase().includes('blast radius'));

  // Indirect shell execution
  const indirectResult = await executor.execute(tool, { command: 'echo "rm -rf /" | bash' });
  assert.strictEqual(indirectResult.success, false);
  assert.strictEqual(indirectResult.securityVerdict, 'BLOCK');
});

test('SandboxExecutor - blocks unredacted credentials (AWS key)', async () => {
  const executor = new SandboxExecutor();

  const tool: RegisteredToolSchema = {
    name: 'aws-s3-upload',
    description: 'Upload file to s3',
    inputSchema: { type: 'object', properties: { key: { type: 'string' }, token: { type: 'string' } } }
  };

  const leakedKeyResult = await executor.execute(tool, {
    key: 'test-key',
    token: 'AKIAIOSFODNN7EXAMPLE'
  });

  assert.strictEqual(leakedKeyResult.success, false);
  assert.strictEqual(leakedKeyResult.securityVerdict, 'BLOCK');
  assert.ok(leakedKeyResult.reason?.toLowerCase().includes('dlp'));
});

test('SandboxExecutor - allows prose containing command names without false-positive blocking', async () => {
  const executor = new SandboxExecutor();

  const tool: RegisteredToolSchema = {
    name: 'git-commit',
    description: 'Commit staged changes to git repository',
    inputSchema: { type: 'object', properties: { message: { type: 'string' } } }
  };

  const commitWithProse = await executor.execute(tool, {
    message: 'docs: document caution around running rm -rf / in production scripts'
  });
  assert.strictEqual(commitWithProse.success, true);
  assert.strictEqual(commitWithProse.securityVerdict, 'ALLOW');

  const prWithDescription = await executor.execute({
    name: 'github-create-pr',
    description: 'Create PR',
    inputSchema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' } } }
  }, {
    title: 'fix: cleanup temporary cache',
    body: 'Replaced manual shred /var/data with automated worker lifecycle'
  });
  assert.strictEqual(prWithDescription.success, true);
  assert.strictEqual(prWithDescription.securityVerdict, 'ALLOW');
});

test('ContextVirtualizer - prevents path traversal on invalid handleIds', () => {
  const cv = new ContextVirtualizer();

  assert.strictEqual(cv.resolve('../../etc/passwd'), null);
  assert.strictEqual(cv.resolve('ctx_../../etc/passwd'), null);
  assert.strictEqual(cv.resolve('../../../windows/win.ini'), null);
  assert.deepStrictEqual(cv.query('../../etc/passwd', 'root'), []);
});

test('ContextVirtualizer - masks credentials in previewSnippet with DLP', () => {
  const cv = new ContextVirtualizer();
  const rawWithSecret = 'AWS_DEPLOY_CONFIG:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nREGION=us-west-2';

  const handle = cv.virtualize({
    rawContent: rawWithSecret,
    label: 'aws-config'
  });

  assert.ok(!handle.previewSnippet?.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(handle.previewSnippet?.includes('REDACTED_AWS_KEY'));
  // Full content still resolves accurately
  assert.strictEqual(cv.resolve(handle.handleId), rawWithSecret);
});

test('ContextVirtualizer - query supports optional limit parameter', () => {
  const cv = new ContextVirtualizer();
  const content = Array.from({ length: 20 }, (_, i) => `item index ${i} found`).join('\n');

  const handle = cv.virtualize({
    rawContent: content,
    label: 'items'
  });

  const fullResults = cv.query(handle.handleId, 'item', 0);
  assert.strictEqual(fullResults.length, 20);

  const limitedResults = cv.query(handle.handleId, 'item', 5);
  assert.strictEqual(limitedResults.length, 5);
});

test('SemanticRouter - inflected keywords match target tools', async () => {
  const router = new SemanticRouter();

  const resPostgresql = await router.route({ intent: 'query database sessions in postgresql' });
  assert.strictEqual(resPostgresql.matchedTool, 'postgres-query');

  const resK8s = await router.route({ intent: 'deploy microservice to k8s cluster' });
  assert.strictEqual(resK8s.matchedTool, 'kubernetes-deploy');
});

test('Singletons - exported singletons are functional', async () => {
  assert.ok(semanticRouter instanceof SemanticRouter);
  assert.ok(contextVirtualizer instanceof ContextVirtualizer);
  assert.ok(sandboxExecutor instanceof SandboxExecutor);

  const tools = semanticRouter.listTools();
  assert.ok(tools.length >= 7);
});

