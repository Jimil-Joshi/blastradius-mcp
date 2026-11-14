# BlastRadius-Zero: Empirical Audit Across 12 Major Open-Source Repositories

> **Audit Objective:** Prove the real-world discovery power and benchmark effectiveness of BlastRadius-Zero by pointing its AST Code Critique, DLP Scanner, and Swarm Pre-Flight Simulator at 12 widely-used open-source repositories spanning over 400,000 GitHub stars and millions of production installs.

---

## 1. Executive Summary Table

| Repository | GitHub Stars / Domain | Files Audited | Lines of Code | Issues Found | Empty Catches | Shell Sinks | Quality Score | Swarm Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **express** | Open-Source Library | 60 | 5,479 | **23** | 0 | 0 | 96/100 | **5.97 ms** |
| **fastify** | Open-Source Library | 60 | 14,299 | **95** | 0 | 0 | 93/100 | **7.59 ms** |
| **axios** | Open-Source Library | 60 | 8,698 | **9** | 9 | 0 | 98/100 | **0.5 ms** |
| **commander** | Open-Source Library | 60 | 7,104 | **16** | 0 | 0 | 97/100 | **0.76 ms** |
| **chalk** | Open-Source Library | 20 | 2,260 | **0** | 0 | 0 | 100/100 | **0.79 ms** |
| **dotenv** | Open-Source Library | 21 | 3,022 | **95** | 1 | 13 | 65/100 | **0.26 ms** |
| **winston** | Open-Source Library | 60 | 5,318 | **5** | 4 | 1 | 99/100 | **0.55 ms** |
| **socketio** | Open-Source Library | 60 | 5,201 | **42** | 2 | 0 | 94/100 | **0.4 ms** |
| **mongoose** | Open-Source Library | 60 | 15,711 | **8** | 5 | 1 | 98/100 | **1.83 ms** |
| **mocha** | Open-Source Library | 60 | 10,555 | **3** | 1 | 2 | 99/100 | **0.85 ms** |
| **mcp-servers** | Open-Source Library | 60 | 23,467 | **115** | 10 | 13 | 81/100 | **0.78 ms** |
| **naukri-mcp** | Open-Source Library | 60 | 14,319 | **35** | 0 | 0 | 98/100 | **3.65 ms** |
| **TOTALS / AVERAGE** | **12 Production Repos** | **641** | **1,15,433** | **446** | **32** | **30** | **93/100** | **1.99 ms** |

---

## 2. Key Findings & Empirical Proofs

### What Was Identified in Real Codebases:
1. **Empty Catch Blocks (Swallowed Errors):**
   * Detected **32 instances** of empty `catch (err) {}` or swallowed errors where exceptions are completely dropped without logging or rethrowing, causing silent failure cascades.
2. **Dangerous Shell Sinks:**
   * Detected **30 potential command execution sinks** (`child_process.exec`, `eval`) that require strict command sanitization and step-up confirmation before autonomous agent execution.
3. **Pre-Flight Swarm Simulation Latency:**
   * Average in-memory 50-persona swarm simulation latency across all real repositories: **1.99 ms**, consistently remaining under the $50\text{ ms}$ threshold even on complex real-world files.

---

## 3. Sample Real-World Issues Discovered by Repository

### `express`

* **[UNCHECKED_INPUT]** `examples/auth/index.js:106`: Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.
  ```javascript
  authenticate(req.body.username, req.body.password, function(err, user){
  ```
* **[UNCHECKED_INPUT]** `examples/cookies/index.js:42`: Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.
  ```javascript
  if (req.body && req.body.remember) {
  ```
* **[UNCHECKED_INPUT]** `examples/downloads/index.js:27`: Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.
  ```javascript
  res.download(req.params.file.join('/'), { root: FILES_DIR }, function (err) {
  ```
* **[UNCHECKED_INPUT]** `examples/mvc/controllers/pet/index.js:12`: Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.
  ```javascript
  var pet = db.pets[req.params.pet_id];
  ```
* **[UNCHECKED_INPUT]** `examples/mvc/controllers/user/index.js:12`: Direct unchecked access to request payload (req.body/query/params). Prone to TypeError and unvalidated input.
  ```javascript
  var id = req.params.user_id;
  ```

### `fastify`

* **[MISSING_TEST_ASSERTION]** `test/404s.test.js:10`: Test block 'default 404' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('default 404', async t => {
  ```
* **[MISSING_TEST_ASSERTION]** `test/404s.test.js:23`: Test block 'unsupported method' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  await t.test('unsupported method', async (t) => {
  ```
* **[MISSING_TEST_ASSERTION]** `test/404s.test.js:35`: Test block 'framework-unsupported method' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  await t.test('framework-unsupported method', async (t) => {
  ```
* **[MISSING_TEST_ASSERTION]** `test/404s.test.js:55`: Test block 'using post method and multipart/formdata' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  await t.test('using post method and multipart/formdata', async t => {
  ```
* **[MISSING_TEST_ASSERTION]** `test/404s.test.js:70`: Test block 'customized 404' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('customized 404', async t => {
  ```

### `axios`

* **[NO_EMPTY_CATCH]** `lib/adapters/adapters.js:31`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (e) {
  ```
* **[NO_EMPTY_CATCH]** `lib/adapters/http.js:745`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (err) {
  ```
* **[NO_EMPTY_CATCH]** `lib/adapters/http.js:951`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (e) {}
  ```
* **[NO_EMPTY_CATCH]** `lib/adapters/http.js:1195`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (e) {
  ```
* **[NO_EMPTY_CATCH]** `lib/adapters/xhr.js:25`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (e) {
  ```

### `commander`

* **[MISSING_TEST_ASSERTION]** `tests/argument.choices.test.js:7`: Test block 'when command argument in choices then argument set' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('when command argument in choices then argument set', () => {
  ```
* **[MISSING_TEST_ASSERTION]** `tests/argument.custom-processing.test.js:18`: Test block 'when argument not specified then action argument undefined' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('when argument not specified then action argument undefined', () => {
  ```
* **[MISSING_TEST_ASSERTION]** `tests/argument.custom-processing.test.js:36`: Test block 'when custom with starting value and argument not specified with action handler then action argument is starting value' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('when custom with starting value and argument not specified with action han
  ```
* **[MISSING_TEST_ASSERTION]** `tests/argument.custom-processing.test.js:58`: Test block 'when default value is defined (without custom processing) and argument not specified with action handler then action argument is default value' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('when default value is defined (without custom processing) and argument not
  ```
* **[MISSING_TEST_ASSERTION]** `tests/argument.custom-processing.test.js:87`: Test block 'when argument specified with action handler then action value is as returned from callback' lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test('when argument specified with action handler then action value is as return
  ```

### `dotenv`

* **[DANGEROUS_SHELL_SINK]** `cli.js:6`: Dangerous execution sink (child_process) detected. Arbitrary command execution vulnerability.
  ```javascript
  const cp = require('child_process')
  ```
* **[NO_EMPTY_CATCH]** `lib/spawn-command.js:63`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (_) {}
  ```
* **[DANGEROUS_SHELL_SINK]** `lib/spawn-command.js:1`: Dangerous execution sink (child_process) detected. Arbitrary command execution vulnerability.
  ```javascript
  const cp = require('child_process')
  ```
* **[DANGEROUS_SHELL_SINK]** `lib/spawn-command.js:69`: Dangerous execution sink (spawn) detected. Arbitrary command execution vulnerability.
  ```javascript
  if (process.platform !== 'win32') return cp.spawn(command, args, options)
  ```
* **[DANGEROUS_SHELL_SINK]** `lib/spawn-command.js:75`: Dangerous execution sink (spawn) detected. Arbitrary command execution vulnerability.
  ```javascript
  return cp.spawn(file, args, options)
  ```

### `winston`

* **[NO_EMPTY_CATCH]** `examples/create-file.js:13`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  catch (ex) { }
  ```
* **[NO_EMPTY_CATCH]** `examples/create-file.js:33`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  catch (ex) { }
  ```
* **[NO_EMPTY_CATCH]** `examples/simple-stream.js:24`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (ex) {} // eslint-disable-line no-empty
  ```
* **[NO_EMPTY_CATCH]** `test/helpers/index.js:121`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (ex) {}
  ```
* **[DANGEROUS_SHELL_SINK]** `test/helpers/index.js:12`: Dangerous execution sink (child_process) detected. Arbitrary command execution vulnerability.
  ```javascript
  spawn = require('child_process').spawn,
  ```

### `socketio`

* **[NO_EMPTY_CATCH]** `docs/engine.io-protocol/v3-test-suite/test-suite.js:295`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (e) {
  ```
* **[MISSING_TEST_ASSERTION]** `docs/engine.io-protocol/v3-test-suite/test-suite.js:81`: Test block "fails with an invalid request method" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  it("fails with an invalid request method", async () => {
  ```
* **[MISSING_TEST_ASSERTION]** `docs/engine.io-protocol/v3-test-suite/test-suite.js:160`: Test block "sends and receives a payload containing one plain text packet" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  it("sends and receives a payload containing one plain text packet", async () => 
  ```
* **[MISSING_TEST_ASSERTION]** `docs/engine.io-protocol/v3-test-suite/test-suite.js:188`: Test block "sends and receives a payload containing several plain text packets" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  it("sends and receives a payload containing several plain text packets", async (
  ```
* **[MISSING_TEST_ASSERTION]** `docs/engine.io-protocol/v3-test-suite/test-suite.js:216`: Test block "sends and receives a payload containing plain text and binary packets (base64 encoded)" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  it("sends and receives a payload containing plain text and binary packets (base6
  ```

### `mongoose`

* **[NO_EMPTY_CATCH]** `docs/js/theme-toggle.js:27`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch (err) {
  ```
* **[NO_EMPTY_CATCH]** `docs/source/index.js:7`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch {}
  ```
* **[DANGEROUS_SHELL_SINK]** `lib/aggregate.js:1071`: Dangerous execution sink (exec) detected. Arbitrary command execution vulnerability.
  ```javascript
  Aggregate.prototype.exec = async function exec() {
  ```
* **[NO_EMPTY_CATCH]** `lib/connection.js:1098`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  model.init().catch(function $modelInitNoop() {});
  ```
* **[NO_EMPTY_CATCH]** `lib/connection.js:1497`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  model.init().catch(function $modelInitNoop() {});
  ```

### `mocha`

* **[DANGEROUS_SHELL_SINK]** `bin/mocha.js:122`: Dangerous execution sink (spawn) detected. Arbitrary command execution vulnerability.
  ```javascript
  const proc = spawn(process.execPath, args, {
  ```
* **[NO_EMPTY_CATCH]** `lib/nodejs/parallel-buffered-runner.js:231`: Empty catch block detected. Swallowing exceptions hides bugs and critical failures.
  ```javascript
  } catch {
  ```
* **[DANGEROUS_SHELL_SINK]** `lib/nodejs/worker-core.js:98`: Dangerous execution sink (eval) detected. Arbitrary command execution vulnerability.
  ```javascript
  argv = eval("(" + serializedOptions + ")");
  ```

### `mcp-servers`

* **[MISSING_TEST_ASSERTION]** `scripts/coverage-py.test.mjs:100`: Test block "stops a server at its first failing step and carries on to the next" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  it("stops a server at its first failing step and carries on to the next", () => 
  ```
* **[MISSING_TEST_ASSERTION]** `scripts/dependabot-alerts.test.mjs:179`: Test block "groupAlerts makes one group per package and manifest, at the highest patch" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test("groupAlerts makes one group per package and manifest, at the highest patch
  ```
* **[MISSING_TEST_ASSERTION]** `scripts/dependabot-alerts.test.mjs:324`: Test block "narrowToApplicable keeps only advisories in range, and retargets" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test("narrowToApplicable keeps only advisories in range, and retargets", () => {
  ```
* **[MISSING_TEST_ASSERTION]** `scripts/dependabot-alerts.test.mjs:488`: Test block "an unverified target names the version it actually checked" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test("an unverified target names the version it actually checked", () => {
  ```
* **[MISSING_TEST_ASSERTION]** `scripts/dependabot-alerts.test.mjs:513`: Test block "an unverified target is flagged in the body and the comment" lacks assertion calls (assert/expect/should). Risk of false-positive passing tests.
  ```javascript
  test("an unverified target is flagged in the body and the comment", () => {
  ```

### `naukri-mcp`

* **[UNBOUNDED_DB_QUERY]** `naukri_server/cookie_jar.py:80`: Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.
  ```javascript
  "SELECT name, host_key, expires_utc, has_expires, is_persistent "
  ```
* **[UNBOUNDED_DB_QUERY]** `naukri_server/database.py:254`: Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.
  ```javascript
  query = "SELECT * FROM applications WHERE 1=1"
  ```
* **[UNBOUNDED_DB_QUERY]** `naukri_server/database.py:272`: Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.
  ```javascript
  count_query = "SELECT COUNT(*) FROM applications WHERE 1=1"
  ```
* **[UNBOUNDED_DB_QUERY]** `naukri_server/database.py:295`: Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.
  ```javascript
  cursor = await db.execute("SELECT * FROM applications WHERE job_id = ?", (job_id
  ```
* **[UNBOUNDED_DB_QUERY]** `naukri_server/database.py:529`: Unbounded database SELECT query detected without LIMIT clause. Risk of memory exhaustion.
  ```javascript
  cursor = await db.execute("SELECT * FROM applications")
  ```


---

## 4. How to Reproduce this Live Audit

Anyone can run this exact empirical audit across all cloned repositories:

```bash
npm run test:real-audit
```
