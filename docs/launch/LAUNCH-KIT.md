# BlastRadius MCP — Launch Kit

Everything here is grounded in code that is in the repository. Every claim has a
file path behind it. Nothing is aspirational, and nothing needs a feature that
does not exist.

**Do not add a claim to any of this without opening the file it points at.** The
single fastest way to lose an investor or a reviewer is to be caught
over-claiming, and this project is asking people to trust it with security
decisions.

---

## Ground rules before you post anywhere

1. **Never say "enterprise-grade", "production-ready", or "battle-tested".** The
   README said these before the audit. They are gone now, and they should stay
   gone until there is evidence.
2. **Never claim complete protection.** It is 17 hand-written rules and 11
   regexes. That is a real guardrail with a real blind spot, and saying so is
   what makes the rest believable.
3. **Always give the count.** 6 tools, 17 rules, 11 detectors, 2 dependencies,
   1,900 lines. Specific numbers are the whole credibility play.
4. **Show the limits.** Agent-supplied `requestedBy`, partial DLP masking that
   leaves 4 characters, `includes()` matching that over-blocks. Mentioning these
   unprompted is the fastest route to being trusted.
5. **Link the repo, not a landing page.** There is no landing page. That is fine.

---

## Hacker News

**Title options** (pick one, do not combine)

- `Show HN: BlastRadius MCP – a zero-trust security proxy for Model Context Protocol servers`
- `Show HN: I built a pre-execution blast radius simulator for AI agent tool calls`
- `Show HN: BlastRadius MCP – scores every MCP tool call 0-100 before it runs`

**Body**

```
BlastRadius MCP is a security proxy you put in front of any Model Context
Protocol server. It scores each tool call 0-100 before the call executes, blocks
the dangerous ones, redacts credentials flowing in either direction, requires a
signed approval token for high-risk actions, and writes a hash-chained audit log.

Apache-2.0. Two runtime dependencies. ~1,900 lines of TypeScript.

Drop it in without touching the server you are guarding:

  npx blastradius-mcp proxy --command "npx -y @modelcontextprotocol/server-filesystem /workspace"

or run it standalone as its own MCP server and call it from your agent.

The problem: giving an agent bash, SQL, or cloud access means a single bad tool
call can drop a database, force-push, or exfiltrate a key. Existing guardrails
either require a hosted service or require you to rewrite your agent loop.

What it actually does:

- 17 hand-written danger signatures across shell, SQL, cloud, and filesystem.
  0-100 danger score, five severity bands. Scoring takes the max matching rule,
  not a sum.
- Environment-aware: the same command scores +20 higher when the context says
  prod, production, live, or main.
- 11 DLP detectors: AWS keys, GitHub PATs, OpenAI, Stripe, Slack, SSH private
  keys, database URI passwords, JWTs, credit cards, SSNs, emails. Redaction
  replaces each match with a typed marker.
- HMAC-SHA256 step-up approval tokens, default 300s TTL, compared with
  timingSafeEqual, scoped to a single tool name, and genuinely single-use.
- SHA-256 hash-chained append-only audit ledger. Payloads are hashed, never
  stored, so secrets don't land in the log. verify_audit_log detects edits and
  broken chain links.
- Proxy mode also scans downstream RESPONSES and redacts credentials before they
  reach the client. A tool that echoes a key back at your agent is a real leak
  path and the proxy closes it without the downstream server knowing.

Six MCP tools: simulate_action, inspect_payload_dlp, enforce_policy,
request_confirmation_token, verify_audit_log, get_security_posture.

What it does NOT do, so you can decide if it's useful to you: it is rule-based,
not learned. Novel attack shapes are not caught. Path matching is a plain
includes() so it over-blocks (.env matches .envrc). DLP masking leaves the last
4 characters. There is no hosted control plane and no telemetry.

Zero dependencies beyond the MCP SDK and zod. Node 22+.

One note on how this got here: I shipped a version of this with a "24/24 tests
passing" badge and 11 actual tests, four of the six test files empty, a 0-byte
LICENSE file, and a README promising rate limits and SIEM export that did not
exist. A pre-launch audit caught all of it and it is all fixed now. I would
rather lead with that than let you find it.

Repo: https://github.com/Jimil-Joshi/blastradius-mcp
npm:  https://www.npmjs.com/package/blastradius-mcp

Happy to answer questions on the threat model or the scoring.
```

**Posting notes for HN**
- Post between 8:00 and 9:00 ET on a Tuesday, Wednesday, or Thursday.
- The author must be different from whoever is in the comments' replies-to,
  otherwise the submission gets filtered. If Jimil is the sole author, that is a
  real constraint: consider asking a colleague to submit it.
- **Expect and welcome the "your regexes are trivially bypassed" replies.** They
  are correct. Answer directly: yes, rule-based, known-dangerous-17, and the
  audit-log and egress-redaction layers are what cover the gap. Do not get
  defensive. A measured answer to a hostile question is the highest-signal thing
  this launch can produce.
- Do not edit the post to answer questions. Answer in comments.

---

## Reddit

Two different subreddits need two different posts. Do not cross-post the same text.

### r/ClaudeAI or r/mcp

**Title:** `I built a security proxy for MCP servers — it scores every tool call 0-100 before it runs`

**Body**

```
Open source: https://github.com/Jimil-Joshi/blastradius-mcp

Context: if you give an agent bash, filesystem, or SQL access through MCP, you
have probably thought about what happens when it gets something wrong. I built
the thing I wanted to exist.

BlastRadius MCP is an Apache-2.0 proxy that sits between your agent and any MCP
server. Every tools/call gets scored 0-100 for blast radius before it runs.

Some specifics since vague security posts are common here:

- 17 hand-written rules across shell/SQL/cloud/filesystem. rm -rf / is 100,
  DROP DATABASE is 100, a DELETE with no WHERE is 90, curl | sh is 90,
  k8s cluster-wide deletes are 95.
- The same command scores +20 higher if the context environment is prod/live/main.
- 11 DLP detectors with actual redaction, including AWS keys, GitHub PATs,
  OpenAI, Stripe, Slack, SSH private keys, DB URI passwords, JWTs, cards, SSNs.
- Approval tokens for HIGH and CRITICAL actions: HMAC-SHA256, 5 min TTL,
  timingSafeEqual, single tool scope, and actually single-use.
- SHA-256 hash-chained audit log. Hashes the payload instead of storing it, so
  your secrets don't end up in your audit trail.
- Proxy mode redacts credentials coming BACK from the downstream server. This
  is the part I care about most, because tools echo keys constantly and nobody
  redacts on egress.

Two runtime dependencies. Node 22+. No hosted component, no API calls, no
telemetry, nothing phoned home.

Limits, stated plainly: it's rule-based, so novel attacks slip through. Path
matching is a plain includes() and will over-block. Masking keeps the last 4
characters by design so you can tell two keys apart. It is a guardrail, not a
walled garden.

Feedback very welcome, especially on the rule set. If you have a dangerous
command pattern that isn't covered, I want to know about it.
```

### r/ExperiencedDev or r/devops

Frame this as an engineering-post-mortem rather than a product pitch. The
self-audit story outperforms the feature list with this audience.

**Title:** `We shipped a security tool with a fake test badge. Here's the audit that caught it and what it cost.`

**Body**

```
Posting the audit rather than the product because the audit is the more useful
part.

I built an open-source MCP security proxy, and hours before launching it I read
the README against the actual code. Five things did not match.

1. The badge said "tests 24/24 passed". There were 11 tests, in 2 files. Four of
   the six test files were 0 bytes. The audit ledger, the policy engine, the
   token manager, and the end-to-end server had zero coverage. Eight of the
   seventeen test names in the README's sample output existed in no file at all.

2. The README said approval tokens were "single-use with replay protection". The
   consumeToken() function existed, was documented, and was never called. The
   replay check read a Set that nothing ever wrote to, so tokens stayed valid
   for their full TTL and replayed freely. A security control that sounds like
   it works and does not is worse than not having it, because it changes what you
   believe about your system.

3. --policy parsed a custom security config, printed a log line, and dropped it
   on the floor. Neither the server nor the proxy received the object. The
   example policy file in the repo affected nothing.

4. LICENSE was 0 bytes while package.json said Apache-2.0. Anyone who cloned it
   got no license grant. Dockerfile and smithery.yaml were also 0 bytes, behind
   a "1-Click Ready" badge.

5. The README promised 1,000 calls/hour, x402 micropayments, and Splunk SIEM
   export. None existed. The license "validator" was a string prefix check that
   gated nothing, and an Apache-2.0 repo could not enforce a paywall anyway.

All five are fixed. The token is now consumed at the moment it authorises an
action. The policy is threaded through. There's a real CI gate and a real test
suite. The paid tiers are gone.

The part I keep coming back to: those five would have been the public face of a
product whose entire pitch is that it stops agents from doing dangerous things.
The over-claiming was the vulnerability. Fixing it took less time than writing
this post.

Repo if useful: https://github.com/Jimil-Joshi/blastradius-mcp

The general lesson I took: if your tool is about trust, your build pipeline and
your README are part of the product surface. An empty test file and a badge that
disagrees with the code is a supply chain issue, whatever your code does.
```

---

## Product Hunt

Product Hunt needs positioning, not a changelog. Lead with the audience and the
before/after.

- **Name:** BlastRadius MCP
- **Tagline:** *The firewall between your AI agent and production.*
- **Categories:** Developer Tools, Security, Artificial Intelligence
- **First comment (posted by you, immediately):**

```
Thanks for trying it.

The honest framing: agents with bash or SQL access will eventually do something
destructive, and today most guardrail options either need a hosted service or
need you to rewrite your agent loop. BlastRadius is a proxy that goes in front
of any MCP server instead, so there is no loop to rewrite.

It's Apache-2.0 with two runtime dependencies, runs locally, and phones nothing
home.

Try the 10 second version:
  npx blastradius-mcp proxy --command "npx -y @modelcontextprotocol/server-filesystem /workspace"

Then ask your agent to delete something it shouldn't.

Under the hood: 17 hand-written danger signatures scored 0-100 with five
severity bands, the same command scoring +20 higher against a production
environment. 11 DLP detectors that redact AWS keys, GitHub PATs, OpenAI, Stripe,
Slack, SSH keys, DB passwords and JWTs. HMAC-signed single-use approval tokens
for high-risk actions. A SHA-256 hash-chained audit ledger that stores hashes
instead of payloads. And egress redaction, which I think is the underrated one:
it scrubs credentials coming back OUT of tools before they reach the model.

It's rule-based rather than learned, so it has a blind spot for novel attacks.
I'd rather say that up front. If you have dangerous command patterns that aren't
covered, open an issue, the rule set is the part I most want help with.

GitHub: https://github.com/Jimil-Joshi/blastradius-mcp
```

- **Maker comment reply to the first critical question:** agree immediately. The
  fastest way to a good Product Hunt thread is to be the commenter who concedes
  the obvious limitation before anyone else does.

---

## X / Twitter

Thread, 6 posts. Hook is the audit, not the product.

```
1/ I shipped a security product with a badge that said "24/24 tests passing."
   There were 11 tests. Four of my six test files were 0 bytes.

🧵

2/ The bad ones were the good ones to read.

   - approval tokens claimed "replay protection". The function existed, was
     documented, and was never called. The check read a Set nothing wrote to.

3/ --policy parsed a custom security config, logged "loaded," and dropped it.
   The example policy file in my repo affected nothing at all.

4/ LICENSE was 0 bytes while package.json said Apache-2.0. So anyone who
   cloned it got no license grant. Dockerfile too. Behind a "1-Click Ready"
   badge.

5/ The README promised rate limits, x402 micropayments, and Splunk SIEM
   export. None of it existed. The license validator was a string prefix check
   that gated nothing.

6/ All fixed. Tokens are consumed at the moment they authorize. The policy is
   threaded through. Real CI, real tests, paid tiers deleted.

   A tool whose pitch is "I stop agents doing dangerous things" was itself
   over-claiming. That was the bug.

   github.com/Jimil-Joshi/blastradius-mcp
```

---

## Dev.to / Hashnode

Title: `I found 5 false claims in my own security tool's README. Here's what that taught me about shipping security software.`

Long-form, technical, and the audience rewards exactly this. Sections:
1. The badge that lied (test counts)
2. The control that didn't exist (token replay)
3. The flag that did nothing (`--policy`)
4. The empty files (LICENSE, Dockerfile)
5. The features that were fiction (rate limits, x402, SIEM)
6. Why this class of bug is worse than a normal bug
7. What I changed, with the before/after diffs
8. What I'd build into every security repo from now on

Include the real diffs. Reviewers will check them, and they prove nothing was
hand-waved.

---

## MCP Directories

| Directory | Action | Notes |
|---|---|---|
| smithery.ai | Submit | `smithery.yaml` is now real, not 0 bytes. Requires npm publish to be live first. |
| glama.ai | Submit | `glama.json` exists. Glama runs a security review, which is the point. |
| mcp.so | Submit | Free listing, needs npm live. |
| pulsemcp.com | Submit | Add to the MCP directory manually. |
| GitHub `modelcontextprotocol/servers` | Open a PR | This is the official community list and the single highest-value directory entry. Do it personally, in a browser, with a good description. |
| awesome-mcp | PR to an existing list | Same reasoning. |

All of these require the npm package to be re-published first, because they read
the live package. That means the fix has to be released before the listing
campaign starts.

---

## Sequencing

Wrong order wastes the launch.

1. Land the fixes. Merge the PR. Let CI go green.
2. `npm publish` a corrected version. Verify `npx -y blastradius-mcp` actually
   runs from a clean machine, not from your dev folder.
3. Set GitHub topics and the social preview image.
4. Post the HN/Reddit material. These are the credibility plays and they need a
   green CI badge to land on the repo.
5. File the directory listings.
6. LinkedIn. This is the sustained-motion channel, not the launch spike.
7. DM the people whose work you cite or whose tools you integrate.

Steps 1 and 2 are prerequisites for all of the rest.
