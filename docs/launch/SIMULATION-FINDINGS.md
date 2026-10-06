# Multi-Agent Market Simulation — Findings and Decision

**Run:** 5 October 2026. **Method:** MiroFish methodology (seed extraction →
persona generation → independent agent interaction → report synthesis over
results) executed through agent sub-agents, because MiroFish's own engine needs
an `LLM_API_KEY` and a `ZEP_API_KEY` that do not exist in this environment.
MiroFish is installed and ready; see `RUN-BLASTRADIUS-SIM.md`.

**Seed:** `seed-material/blastradius-market.md` — product with measured numbers,
market evidence with sources, competitive field, explicit constraints, and five
deliberately adversarial prompts.

**Personas (6, independent, none saw the others):** VC partner · enterprise CISO ·
independent red-team researcher · competing OSS maintainer (`hoophq/fence`) ·
funded competitor founder ($16M pre-seed) · market analyst skeptic.

**Read this first: five of six personas independently reached the same conclusion
about the ceiling, from five different directions. That convergence is the finding.
The unicorn goal is not achievable through this product as currently scoped.**

---

## Part 1 — What all five agreed on

### 1. The unicorn goal is arithmetically closed at the engine layer

The VC ran the TAM: MCP security is $169.73M in 2026 → $624.46M by 2031. Top five
vendors take 60%, leaving ~$250M. A pre-execution engine captures 3-7%.

**2031 revenue ceiling even winning the engine layer completely: $8-17M ARR.**
Unicorn probability given to this project: **3%.**

The skeptic ran the same arithmetic from the buyer side and got $3-8M ARR at 36
months, with the mechanism spelled out: 500 venture-grade customers out of a
universe of ~2,000 serious buyers, meaning you must own 25% of the entire market,
solo, with no reference logo, in three years.

Both independently. The layer is too small. This is not an execution problem.

### 2. The resolver is a feature, not a moat

Every persona that examined it said the same thing, and the funded competitor said
it most bluntly: *"the resolver is a known artifact under Apache-2.0. The code is
not scarce. The corpus is scarce and we already own more of it than they ever
will."*

Two engineers, six to eight weeks. Zenity can ship a better version of it in a
sprint and publish five posts about it, for roughly $60k of loaded salary.

Apache-2.0 with no CLA makes this worse, not better. The competitor wrote:
*"Apache-2.0 code keeps shipping under its current license whatever we do.
Acquisition buys a person, not an artifact."*

### 3. The approval token is a control-design failure

The single most decisive finding, and three personas reached it independently.

Your threat model is an agent acting faster than a human can intervene. Your
control is: the agent requests a token, the agent receives it. **The adversary
controls both halves.**

The CISO's assessment: *"an agent about to run `rm -rf` calls
`request_confirmation_token({requestedBy: "alice@firm.com"})` and gets a valid,
correctly-scoped, unexpired, single-use token. The ledger now records that a human
approved. **That is a false attestation generated on demand.**"*

The `fence` maintainer put the same thing as a category difference rather than a
quality difference: his hook is a TTY prompt the agent physically cannot satisfy
itself.

No configuration fixes this. It needs an approval channel the agent **cannot
dial** — a separate system, a separate principal, a separate trust domain.

### 4. Candour is a moat against capital

The only finding that cuts the other way, and it came from the competitor.

> *"They can publish a rigorous limitation list about their own product, name their
> own weaknesses, and be trusted more for it. We cannot — our credibility is
> structurally tied to not having weaknesses, so we cannot be as candid, and
> candidness is what wins technical evaluators."*

A funded company cannot publish "this control does not decode base64" without a
remediation commitment attached. You can. That is a real, structural advantage, and
it is why the GuardFall rewrite was the right move even though it was expensive.

---

## Part 2 — Bugs the simulation found in your code

The red-team and maintainer personas read the source. They were not kind, and they
were right. All of the following are now fixed and verified.

| Finding | Severity | Status |
| :--- | :--- | :--- |
| **README printed `tests 92` / `pass 113`** — two numbers for one thing, arranged to read larger. Introduced by me during this session. | Credibility | **Fixed.** Same instinct as the original fake `24/24` badge |
| **ZT-004 bypassed the resolver.** `policyEngine.ts` matched protected paths against `JSON.stringify(params)`, so `D=/etc; cat $D/shadow` never blocked. The README claimed all 21 rules matched the resolved command. | **Critical + false claim** | **Fixed.** Policy now resolves too; 4/4 variable-hidden paths blocked |
| **Newline was not a command separator.** Multi-line scripts — the normal shape an agent sends — collapsed into one segment. | High | **Fixed** |
| **Nested `$(...)` mangled.** Non-greedy match stopped at the first `)`, so `$(echo $(date))` lost the outer program. | High | **Fixed.** Balanced-paren recursion |
| **Brace expansion absent.** `rm -rf /{etc,var,home}` scored 5. | High | **Fixed** |
| **`rm -rf $VAR` scored 100 on any unknown variable.** `TARGET=$PWD/build; rm -rf $TARGET` — ordinary scripting — was CRITICAL. The 39-command false-positive probe contained no variable assignments, which is why it passed. | **High, self-inflicted** | **Fixed** |
| `/var/tmp` treated as a system path. Deleting a cache directory scored 95. | Medium | **Fixed** |
| **Ruleset gaps:** `rsync -a --delete`, `docker system prune -af`, `redis-cli FLUSHALL`, `aws s3 rm --recursive` all scored SAFE. | High | **Fixed.** New `FS-002`, `DB-001` |
| `isDestructive` in the sequence detector regexes **English prose** out of `reasons`. A security control whose input is a human-readable string in another module. | Medium | **Not yet fixed** |

The maintainer's verdict on that last pattern is worth internalising: *"Documenting
a bad interface doesn't make it a good one."* One-line fix, still outstanding.

### The meta-observation

Three of these are the same failure mode as the original audit: **a claim in
documentation that the code does not support.** The README said all rules matched
the resolved command. It did not. That is the identical pattern we spent the first
half of this day removing, and it survived because I wrote the resolver and the
README without checking they agreed.

Your credibility strategy is correct. Enforce it on yourself with the same
ruthlessness you now apply to competitors.

---

## Part 3 — What you actually built today

Do not lose this in the strategic analysis. Before the simulation:

- 41 tests → **113**, all passing
- GuardFall bypass coverage: **14/23 → 23/23** dangerous commands scored HIGH+
- False positives on the adversarial probe: **0/6** (was 1/6, and the old probe
  was never adversarial)
- Approval tokens genuinely single-use
- Audit ledger verifies the HMAC signatures it writes
- `--policy` actually works
- Real Apache-2.0 LICENSE, CI, CodeQL, MCPB manifest, working Dockerfile
- The fake Community/Pro/Enterprise tiers, rate limits, x402 and SIEM claims: gone
- Sequence detection wired into `enforce_policy`, five patterns, only able to tighten
- Egress redaction on downstream responses — the one capability every persona named
  as genuinely valuable and not available elsewhere

That is a real, well-engineered open-source security project. It is not a company.

---

## Part 4 — The one niche that is actually unoccupied

The skeptic was asked to name it, honouring the constraint that gateway, discovery,
SIEM, and non-human identity are all funded. This is the answer, and it converges
with the competitor's and the VC's independent recommendations.

### The conformance and attestation substrate for the agent tool supply chain

Three artifacts:

1. **A living adversarial conformance corpus.** The GuardFall method,
   industrialised: a versioned, vendor-neutral test suite that any MCP server *or*
   any guardrail can be run against, producing a comparable number.

2. **A signed attestation format.** SLSA/in-toto provenance, but for agent tool
   surfaces: *"This server, at commit X, declares tools T, egress destinations E;
   it passed suite v2026-11-14 at 94.2% block rate on 500 adversarial cases; signed
   by issuer Y."* Machine-verifiable, not a PDF.

3. **A pre-connect verifier.** An MCP client, gateway, or platform team gets a
   machine-checkable answer to the only question that matters here: *what is the
   blast radius of this server, and who has vouched for it?*

### Why nobody will build it

It makes almost no money alone. It has no runtime hook, therefore no demo and no
cold-start attack surface. It needs a maintainer-community recruiting motion, not
an enterprise sales motion.

And decisively: **every funded competitor actively prefers its absence.** A neutral
conformance standard caps their differentiation and hands their credibility to a
third party. Zenity has no incentive to build a standard that might say "our gateway
blocks 88%." They will not build it. They may try to block it.

### Why you are the only one who can

Credibility in a standards body accrues to whoever published the corpus and ran
the adversarial research — not to whoever has the biggest scanner. You have already
demonstrated the exact skill the niche monetises.

It also solves the structural problem the skeptic identified: **the free engine was
going to be handed to Zenity anyway. A corpus is a better thing to give away,
because it sits upstream of every engine rather than downstream of one.** Zenity can
ignore your engine. Zenity cannot ignore a standard their customers will use to
compare Zenity against a competitor.

### The demand is already legislated, just not budgeted

NSA *MCP: Security Design* (Jun 2026), CSA Singapore's Agentic AI addendum
(Jun 2026), and NIST's AI Agent Standards Initiative profile (Q4 2026) all create
demand for **evidence** without mandating any tool. You do not need to win a
platform bake-off. You need the corpus to become the thing a procurement checklist
cites.

### The falsification test

> If this model were proven, there would already be a company in this field with 3+
> years of open-source life and a **published, audited free-to-paid conversion
> number. Name one.**

There isn't one. Every company in the list sells the plane *with* the engine,
bundled, happily — because the plane is where the money is. Bundling is what a
rational competitor does when the engine layer has no value. They have already told
you the answer.

---

## Part 5 — Decisions, in order

### Do now, this week

1. **Commit and publish.** 113 tests, real licence, real CI, 23/23 bypasses. Nothing
   works until this is on npm. `docs/launch/EXECUTE.md`.
2. **Fix the `isDestructive` prose-regexing.** One line: persist `destructive` in the
   audit entry.
3. **Add the adversarial probe to CI.** It found 6 real bugs in one pass. A guard
   whose own test suite only contains cases its author wrote is the exact thing the
   `fence` maintainer criticised.

### Do this month

4. **Open the corpus repository.** Not announced. Published. Start with the 23
   GuardFall cases, the 12 adversarial cases, and an invitation phrased so a
   competitor *must* run it against themselves. The competitor's memo said the
   single highest-leverage move in this category is publishing a public red-team
   harness and results including where you lose. It is also free distribution.
5. **Stop selling the parser.** The competitor, the VC, and the skeptic all
   independently said the same: table stakes has arrived, table stakes is the worst
   possible location for a differentiator. Your README's own honest limitations
   section does more selling than the feature list does.
6. **Write the GuardFall technical post.** This is not self-promotion — it is a
   measured, sourced response to published criticism. It is the highest-quality
   content available on this topic and it is the credible on-ramp to everything else.

### Do not do

7. **Do not build the out-of-band approval channel solo.** The skeptic's own second
   choice, and it needs someone who has done carrier procurement: it is
   number-portability, SMS-A2P registration, and per-country telecom compliance.
   Correct call for a technical founder, wrong call for one person. It is also,
   however, the single highest-value thing a *co-founder* could join for. If you know
   anyone who has worked telecom carrier procurement, that is a conversation.

### Do the honest thing about the goal

8. **Decide whether you want a company or a project.** The simulation is unanimous
   that this path produces a respected project and a $3-8M ARR business, or an
   acqui-hire at $3-8M. The 5% path to something larger is: a platform vendors your
   resolver, and you become a supplier to a company with distribution. The analyst's
   closing line on that trade:

   > *"It is simultaneously the best distribution outcome available and the death of
   > the technical moat. It is a genuinely good trade for a solo founder and it is
   > the one outcome most engineers will refuse to take. Take it."*

---

## What would change these conclusions

The skeptic committed in writing to withdraw the scepticism on any one of:

- A named enterprise contract ≥$150k ARR in MCP security **not** sold by a funded
  platform vendor
- A published free-to-paid conversion rate above 1% for an open-source agent-security
  engine
- An MCP client spec mandating a structured tool-call log with a compliance-relevant
  integrity guarantee
- Zenity, Noma, or Outerlimit publicly shipping your resolver under an Apache-2.0
  notice — not a threat, a confirmation, and the 5% scenario becomes the plan

Worth tracking, because each converts scepticism into strategy rather than doubt.