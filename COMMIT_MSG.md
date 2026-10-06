fix: make security claims true, then resolve commands before matching

The README advertised capabilities the code did not implement. Rather than
soften the claims, this makes them true.

Security fixes:
- Approval tokens are now genuinely single-use. consumeToken() existed and was
  never called, so the replay check read a set that nothing wrote to and a token
  stayed valid for its full TTL. Tokens are now consumed the moment they authorise
  an action, and consumed records are pruned by token expiry instead of being
  cleared wholesale.
- The audit ledger now verifies the HMAC signatures it writes. The hash chain
  does not cover severity, category, reasons, or dlpFindingsCount, so editing
  any of those on disk still verified as intact. verifyIntegrity now recomputes
  and constant-time compares every signature.
- Token expiry was off by one second. The check used now > expiresAt, so a
  zero-TTL token was accepted during the second it expired. Now now >= expiresAt,
  and TTLs are capped at one hour so an approval token cannot become a long-lived
  bearer credential.
- --policy was parsed and discarded. The custom policy was loaded and logged
  and then never reached either the server or the proxy, so custom policy files
  had no effect. The policy is now threaded through both constructors.
- Proxy mode could not clear a REQUIRE_CONFIRMATION decision. The
  confirmation token was never passed to the policy engine, so any high-risk action
  through the proxy was permanently unusable. Clients can now supply a
  confirmationToken argument, which is stripped before forwarding downstream.
- Stale build artifacts could ship. dist/ was committed and tsc does not
  prune its output, so a deleted module survived in the published tarball. dist/
  is untracked and npm run build now cleans first.
- Credit card detection missed the common formats. The pattern matched only
  contiguous digits, so 4111 1111 1111 1111 and 4111-1111-1111-1111 passed
  through undetected.
- Four dangerous cloud commands scored as SAFE. terraform destroy,
  terraform apply -auto-approve, aws s3 rb --force, s3 sync --delete,
  helm delete --all, npm publish, and psql -c "TRUNCATE users" all fell
  through to a score of 5. New signatures CLD-004 through CLD-007 cover them,
  and SQL-002 now matches TRUNCATE without the optional TABLE keyword.
- enforce_policy did not report which rule fired. ruleMatched and
  tokenValid are now in the response so clients can see the deciding rule.
- The package lockfile disagreed with package.json, declaring ISC and older
  dependency ranges, so npm ci did not reproduce the tested tree.

Added:
- Shell-aware command resolution (src/analyzer/shellResolver.ts). The engine
  now resolves a command the way a POSIX shell would before matching rules
  against it: quote removal, variable assignment tracking, parameter expansion,
  command substitution, top-level pipeline splitting, and inline program extraction
  for sh -c. Nothing is executed to perform the resolution.
- Structural scoring pass. Facts that only exist once a command is resolved are
  scored directly: destructive binaries aimed at root or home, shred/srm against
  any path, recursive removal of a system path, destruction delegated to find via
  -delete/-exec/-ok, content piped into an interpreter, arguments assembled by
  xargs, and destructive commands composed inline inside sh -c.
- A resolution block on every BlastRadiusReport, exposing the resolved command,
  detected traits, pipeline state, interpreters, and unresolvable variables so a
  reviewer can see the exact text that was matched.
- BLAST_RADIUS_AUDIT_PATH to choose where the ledger is written, instead of
  defaulting to process.cwd().
- get_security_posture reports the build edition, capabilities,
  licenseKeyRequired, and rateLimited instead of a license tier.
- GitHub Actions CI on Node 22 and 24, CodeQL for javascript-typescript, and
  Dependabot.
- SECURITY.md, CONTRIBUTING.md, and this changelog.
- manifest.json for one-click local MCP install, a working multi-stage
  Dockerfile, and ready-to-copy client configs in examples/.
- 104 tests: 41 to 145, covering the resolver, the bypass classes, false-positive
  pinning, structured parameters, ledger tampering in all four modes, and a full
  JSON-RPC lifecycle over stdio.

Removed:
- The license tier system. BLAST_RADIUS_LICENSE_KEY, the Community/Pro/
  Enterprise table, per-hour rate limits, x402 micropayment support, and SIEM
  export were advertised but did not exist in any form. The validator was a string
  prefix check that gated nothing, and an Apache-2.0 repository cannot enforce a
  paywall. BlastRadius is fully open source with no license key and no rate limit.
- smithery.yaml. Smithery's publish flow no longer accepts a stdio config file;
  the manifest.json in this release is the current format.