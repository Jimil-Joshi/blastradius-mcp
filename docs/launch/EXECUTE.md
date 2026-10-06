# Post-launch execution — run these in order

Everything is written and tested locally. Two things need you: a GitHub session, and
a decision to cut the release. Nothing below has been committed or pushed, because
I do not have your GitHub credentials and you did not ask me to commit.

---

## 1. Review before you commit

```bash
cd "C:\Users\Jim-per\MCP's\blastradius-mcp"
git diff --stat
git status --short
```

Worth eyeballing before you stage, because it is a lot of change at once:

- `src/security/licenseValidator.ts` deleted, replaced by `src/security/edition.ts`.
  This removes the fake Community/Pro/Enterprise gating. **You chose this.** An
  Apache-2.0 repo cannot enforce a paywall, so the table was fiction.
- `36 dist/ files` staged for deletion. Build output was committed by mistake and
  the deleted `licenseValidator.js` would have shipped in the npm tarball. The build
  now cleans `dist/` first.
- `smithery.yaml` deleted. Smithery no longer accepts a stdio config file; the
  `manifest.json` in its place is the current format.

## 2. Authenticate

```bash
gh auth login          # if you install GitHub CLI, easiest route
```

There is no `gh` on this machine and no `GITHUB_TOKEN` in the environment, so every
GitHub API call below has to come from you.

## 3. Commit and push

```bash
git add -A
git commit -m "fix: make security claims true, then resolve commands before matching

The README advertised capabilities the code did not implement. Rather than
soften the claims, this makes them true.

Security fixes:
- Approval tokens are now genuinely single-use. consumeToken() existed and was
  never called, so the replay check read a set nothing wrote to.
- The audit ledger now verifies the HMAC signatures it writes. The hash chain
  does not cover severity, category, reasons, or dlpFindingsCount, so editing
  any of those previously verified as intact.
- Token expiry no longer has an off-by-one, and TTLs are capped at one hour.
- --policy was parsed and discarded; it now reaches both the server and the
  proxy.
- Proxy mode can now clear REQUIRE_CONFIRMATION via a confirmationToken
  argument, which is stripped before forwarding downstream.
- The ledger verifies every signature with timingSafeEqual.

Resolution layer:
- New shellResolver resolves quote removal, variable assignments, parameter
  expansion, command substitution, pipelines, and inline sh -c programs before
  any rule matches. Guards that regex the raw command string were measured as
  leaking on most bypass attempts in the GuardFall survey (2026-06-30); 23 of 23
  such cases now score HIGH or above.
- New sequenceDetector detects multi-step workflows over the audit chain:
  exfiltration-then-destruction, reconnaissance-then-exfiltration,
  privilege-ladder, guardrail-probing, destructive-burst.

Packaging and credibility:
- LICENSE was 0 bytes behind an Apache-2.0 badge. Now the real text.
- Dockerfile and .dockerignore were 0 bytes. Now real.
- smithery.yaml deleted; manifest.json added for MCPB one-click install.
- dist/ untracked and the build cleans it first, so deleted modules cannot
  survive into the tarball.
- Lockfile realigned with package.json (it declared ISC).
- Removed the advertised Community/Pro/Enterprise tiers, rate limits, x402, and
  SIEM export. None existed; an Apache-2.0 repo cannot gate them anyway.
- package.json gained repository, homepage, bugs, funding, engines, and files.
- Examples no longer hardcode a local path.

Tests: 41 -> 113, all passing. CI, CodeQL, and Dependabot added."

git push origin main
```

## 4. Cut the release

```bash
npm version minor            # 1.0.0 -> 1.1.0, this is a real feature release
npm publish
```

Then **verify from a clean directory**, not your dev folder. That is the step people
skip, and it is the one the README's quickstart depends on:

```bash
cd $env:TEMP
npx -y blastradius-mcp --version
npx -y blastradius-mcp --help
```

If `--help` prints, the tarball is sound. Every directory listing (Smithery,
Glama, mcp.so, Pulsemcp) reads the published package, so do this before submitting
anywhere.

## 5. GitHub topics

Not settable without auth. One command:

```bash
gh repo edit Jimil-Joshi/blastradius-mcp --add-topic mcp,model-context-protocol,mcp-server,ai-security,agent-security,agentic-ai,security,zero-trust,guardrails,blast-radius,dlp,prompt-injection,audit-log,audit-trail,security-proxy,claude,cursor,proxy,zero-trust-security,secret-scanning,pii-redaction
```

## 6. Social preview image

GitHub picks the first image in the README. There is none, so you get a default
grey card, which costs you click-through on every directory listing.

Generate one at 1280x640 and save it as `docs/social-preview.png`, then reference it
at the top of the README:

```markdown
<p align="center">
  <img src="docs/social-preview.png" alt="BlastRadius MCP" width="1000">
</p>
```

I did not generate it because an AI-generated abstract graphic would undercut the
point of the repo. A dark card with the hook line and the real numbers is better.
If you want one made, say so and I will generate it.

## 7. LinkedIn

Already handled, nothing to do:

- Launch post scheduled **Tuesday 6 Oct, 09:00 IST**, link comment auto-posts with it.
- Comments 1-3 live and verified in-thread: Nicholas White, Rajeev Polepalli, Abayomi I.
- Comments 4-6 scheduled 6, 7, 8 Oct.

## 8. Directories, after the publish

Submit to the official list first. `modelcontextprotocol/servers` is the highest-value
listing on the internet for an MCP server and it is a manual PR.

- [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) — PR, in a browser, with a real description
- Smithery — needs the `.mcpb` bundle: `npm run bundle`
- Glama — `glama.json` already exists
- mcp.so, Pulsemcp, awesome-mcp lists

Copy for all of these is in `docs/launch/LAUNCH-KIT.md`.

---

## What I did not do, and why

- **No commit or push.** No GitHub credentials available, and you did not ask.
- **No `npm publish`.** Same reason. Publishing is the one irreversible step here.
- **No Smithery badge retained.** The old badge claimed a 1-click stdio install that
  the current Smithery flow does not support. It would have been another false claim.
- **No "unique" or "first" framing anywhere.** `hoophq/fence` is a direct analogue at
  21 stars. The pitch is depth on the resolved layer plus sequence detection, not
  absence of competition. Claiming otherwise is the same mistake we removed today.
- **No marketing for the internal fixes.** Per your instruction, the launch shows what
  the tool does, not what was corrected. The fixes are real and documented in
  CHANGELOG.md and the README, for anyone who goes looking.