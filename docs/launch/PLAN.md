# BlastRadius — The Plan

Written 5 October 2026, after: a full source audit, the GuardFall paper, six
independent adversarial personas (VC, CISO, red team, competitor founder,
competing maintainer, market skeptic), NSA/CSA/NIST guidance, and the funding
landscape.

**Read the first section before anything else. It changes what you are building.**

---

## 1. The strategy, stated honestly

You asked how to make this a unicorn. Six personas, five independent directions,
one answer:

> The engine layer's entire 2031 revenue ceiling is **$8-17M ARR**. A unicorn needs
> ~$100M ARR. Not hard, not slow — **arithmetically closed.**

The VC put it plainly: 3% odds of unicorn. The market analyst got to
$3-8M ARR at 36 months from the buyer side and reached the same wall.

**So the parser cannot be the company.** Here is what can.

The one thing every strategic persona converged on, unprompted:

> **The funded competitors are all at the platform layer. None of them will build
> a vendor-neutral conformance standard — because a standard caps their
> differentiation and hands their credibility to a third party.** Zenity has no
> incentive to publish a benchmark that might say "our gateway blocks 88%."

That is a gap created by someone's commercial interest in it staying empty. Gaps
like that do not get filled by the people who benefit from filling them.

### The three products

| | What | License | Who pays |
|---|---| :--- | :--- |
| **1** | **The engine.** Resolve-then-match guardrail, 21+ rules, egress DLP, audit ledger. | **Apache-2.0, free, forever.** | Nobody. It is the distribution. |
| **2** | **The conformance corpus.** A living adversarial test suite any MCP server *or* guardrail can be run against, producing a comparable, versioned number. Plus a CI action. | Free to run; **hosted attestation is paid** | Teams whose customers ask for evidence |
| **3** | **The control plane.** Fleet-wide evidence: continuous attestation, sequence detection across the fleet, export an auditor accepts. | Paid SaaS | Regulated teams, and anyone whose board asks |

The engine is free because **the engine was always going to be given away**. Zenity
can vendor it in a sprint for ~$60k of salary. Making it free does not lose you
that revenue, it stops you pretending to revenue you could never have.

The corpus sits **upstream** of every engine. Zenity can ignore your parser. Zenity
cannot ignore a standard their own customers will use to compare them against a
competitor.

### Why this is not a pivot away from what you built

The GuardFall rewrite is the capability that makes the corpus possible. Only
someone who has run an adversarial evaluation of their own engine can publish an
industry corpus, and the credibility in a standards body accrues to whoever
published it. You have already done the hard part once, publicly.

---

## 2. What to build, in order

### Phase 0 — DONE, this week

An adversarial simulation run before launch found ten verified bypasses scoring
SAFE and five benign commands scoring CRITICAL, including
`npm run build && bash scripts/postbuild.sh`. All are fixed and gated by probe
scripts, not only by unit tests.

| | Before | After |
| :--- | :--- | :--- |
| GuardFall bypass classes caught | 14/23 | **23/23** |
| Red-team bypass classes caught | 0/12 | **12/12** |
| Benign commands over-blocked | 5 (incl. `npm run build`) | **0** |
| Audit-ledger tamper modes detected | 1 of 4 | **4 of 4** |
| Tests | 41 | **145** |

Notable fixes, all from the simulation rather than guesswork:
`{command:'rm', args:['-rf','/']}` — the real MCP input shape — now scores 100 and
BLOCKs. It previously slipped past every text rule, because the JSON contains no
`rm -rf /` substring. The policy gate now has an engine floor so it can never be
more permissive than the engine on the same call.

**Remaining before launch:** `git push` and `npm publish`, then verify
`npx -y blastradius-mcp --help` from a clean directory. `docs/launch/EXECUTE.md`.

**Do not launch with a known bypass.** Ten verified bypasses published alongside a
launch is not a bad first impression, it is the end of the project.

### Phase 1 — weeks 1-4: the corpus repository

**New repo: `blastradius-adversarial`** (or `-conformance`). This is the wedge.

- Start with what you already have: 23 GuardFall classes, 12 adversarial cases,
  18 false-positive pins, 39-command benign corpus. All measured, all publishable.
- Structure: versioned cases, each with `id`, `class`, `payload`, `expected`,
  `citation`. MIT.
- A runner that scores ANY guardrail: `blastradius`, `hoophq/fence`, Continue's
  tokenizer, or a raw-regex baseline. **Include the naive baseline.** Publishing
  "our regex baseline blocks 4%, Continue blocks 94%" is the most useful data point
  in the category and it does not require you to win.
- A CI action: `.github/workflows/mcp-audit.yml`, one line in a customer repo.
- **Publish results including where you lose.** The funded competitor's internal
  memo independently concluded this is the single highest-leverage move available:
  *"publish a versioned public red-team corpus… then run it against everyone
  including ourselves — and publish all of it, including where we lose."*

Distribution is the byproduct: every team that runs the suite is a team that now
knows your name, and the ones that go to your repo are inbound.

### Phase 2 — weeks 3-8: attestation

The corpus is only worth money if its output is portable and checkable.

- **Signed attestation.** SLSA/in-toto provenance shape for agent tool surfaces:
  `server@commit X declares tools T, egress E; passed corpus v2026-11-14 at 94.2%
  on 500 cases; signed by issuer Y`. Machine-verifiable, not a PDF.
- **`blastradius attest <server>`** in the engine repo. Free to run.
- **A pre-connect verifier.** An MCP client, gateway, or platform team gets a
  machine-checkable answer to the only question that matters: *what is the blast
  radius of this server, and who vouched for it?*
- Submit the corpus to the **NIST AI Agent Standards Initiative** (interoperability
  profile expected Q4 2026) and reference it from NSA and CSA guidance. You are not
  selling into those documents; you are making the document's language point at
  something.

### Phase 3 — weeks 6-12: five design partners

**Not five customers. Five design partners who agree to be named.**

The seed material's own question has a sharp answer: the users of a conformance
suite are, by definition, the people who need conformance evidence. They are
already self-qualified and already in your inbound.

Ask each of them the same three questions and write the answers down, verbatim:
1. What broke?
2. What did it over-block?
3. What did it miss?

That document is the seed of the entire commercial roadmap, it is the most
persuasive slide you will ever have, and it cannot be manufactured.

**The sentence that closes a seed round:** *"Here is the bypass the third customer
found in week two. Here is the corpus case it produced. Here is the rule that now
catches it."*

### Phase 4 — months 3-6: the SaaS

Two sellable products. Price both against procurement, not against other startups.

**a. Conformance CI — $99-499/mo per team.** CI runs the corpus on every MCP
server in the estate on every deploy. Emits the attestation. The value is a line
in a customer's procurement checklist, and people pay for checklist lines.

**b. Fleet evidence — $3k-15k/mo.** Aggregated, append-only agent action log with
completeness reconciliation against an independent source — the gap the CISO named
and no one solves. Exports to WORM and SIEM.

**The pricing floor was set for you.** The CISO's own numbers: $25-40k/yr for a
support contract, $50-75k/yr for a component license. That is the market's answer
for an engine with no company behind it, so price above it or not at all. Do not
sell seats. Seats is the wrong unit for a per-tool-call control and it prices the
thing you are trying to constrain.

---

## 3. Stars

Stars are a proxy. Report **weekly npm downloads** and **issues from
non-authors** to investors instead — those cannot be bought.

Realistic: 30-60 stars without committed distribution. 500 with it. The levers, in
order of yield:

| Action | Why it works | Cost |
| :--- | :--- | --- |
| **The GuardFall technical post** | Not self-promotion. A measured, sourced response to published criticism, with the 23 cases and the code that closes them. It is the best content available on this topic because it is honest and reproducible. | 1 day |
| **The corpus repo** | The shareable artifact. Every team running it is a repeat visit. | 3 days |
| **PR to `modelcontextprotocol/servers`** | Official list, manual review, the highest-value listing for any MCP server. | 1 afternoon |
| **Submit to Smithery / Glama / mcp.so / PulseMCP** | They read the published package, so publish first. | 3 hours |
| **Comment on 3 posts/week** | 30-75x more engagement than your own posts. Already running — 3 live, 3 scheduled. | 1 hr/wk |
| **Publish the bypass findings** | `rsync --delete`, `docker system prune`, `redis-cli FLUSHALL` scoring SAFE is a real vulnerability class in a widely-used pattern. Researchers share these. Vendors bury them. | 2 hours |

That last one is underrated and it is free: **you found real mass-deletion bypasses
today.** Publishing them, with credit to nobody, is worth more than any launch
announcement.

---

## 4. Buyers

You have one buyer, and the research identified them precisely.

**Not** the developer. The developer installs it free and becomes the champion.
The developer has no budget and no authority.

**The buyer** is someone whose customer, board, or auditor asked *"show me the log
proving that was blocked."* From the personas:

- **Financial services and regulated industries**, mid-market and up. Kontext's
  customers are almost entirely mid-size and large banks. That is the pattern.
- **AI-native platform teams** at Series A-C companies, 50-300 engineers. Reachable
  today, self-serve, convert when procurement asks for evidence.
- **Anyone running an MCP fleet against servers they do not own.** Regulated, or
  cannot patch a vendor's traversal bug. Underserved, and not `fence`'s user.

The one capability every persona independently named as genuinely valuable and
unavailable elsewhere: **egress redaction on downstream MCP responses.** Your AI
gateway does not see MCP server response bodies. Nothing in the OSS field
addresses it. That is your wedge for the first design-partner conversation.

### What blocks every enterprise sale until you fix it

The CISO's assessment is the checklist. In order:

1. **No legal entity.** Cannot sign an MSA, DPA, or W-9. No insurance. This is a
   hard stop at intake, not a risk you mitigate. Incorporate. It costs a few
   hundred pounds and it is the single cheapest unblock in this document.
2. **The approval token proves nothing about a human.** The agent requests and the
   agent receives. Needs an approval channel the agent **cannot dial** — separate
   system, separate principal, separate trust domain. See the co-founder note below.
3. **4 trailing characters in the audit log.** PCI DSS truncation, GLMA §501(b).
   Fix this week: replace with a hash fingerprint, which correlates the same key
   across occurrences without revealing anything. It is strictly better than what
   you have.
4. **No deletion detection.** Hash chaining verifies what is present. Truncating
   the tail and letting the remainder verify returns `intact: true`. Needs a
   persisted monotonic height.
5. **No SBOM, no signed releases, no `SECURITY.md` SLA.** All cheap.
6. **No out-of-band human channel.** Same as (2).

None of these are engineering problems. Every one is a commitment, and that is
why an entity and a co-founder matter more than another feature.

---

## 5. Investors

### The pitch, in the order that works

Do not lead with the parser. Lead with the three incidents, because everyone in
this category leads with them and nobody has done the arithmetic:

1. **41% of organisations run MCP in production. 38% say security is blocking
   adoption.** The protocol outran its security model. NSA published MCP security
   guidance in June 2026; NIST has an AI Agent Standards Initiative; Singapore's
   CSA issued an addendum. The category exists because institutions created it.
2. **The platform layer is won and I am not competing with it.** Zenity raised
   $125M. Noma $132M. Every one of them sells gateway, discovery, SIEM. I sell the
   thing they would have to build.
3. **The engine layer was empty.** The nearest open-source analogue had 21 stars
   and had not been pushed since August. The engine is now Apache-2.0 with 113
   tests and it is the strongest resolver in the open-source field.
4. **I read the literature and it changed my code.** GuardFall published on 30 June
   measuring my exact design class as bypassable. Goose leaked 22 of 23. I rewrote
   the engine. All 23 now caught.
5. **Nobody will build the standard, which is why it is free.** Every funded
   competitor prefers a vendor-neutral conformance standard not to exist, because
   it caps their differentiation. I published it anyway, and every one of them runs
   it.
6. **Five teams are running it.** Here is the bypass the third one found.

### The two numbers that matter

Not stars. Not downloads.

- **Non-author GitHub issues.** The strongest early signal that real teams use it.
- **Design partners who agree to be named.** Above $150k ARR, or you have a story,
  not a product.

The CISO would have paid **$0** for unpaid OSS on their critical path, at any
price. Every one of the other blockers in their assessment is a commitment, not a
capability. So the raise is not about the parser. It is about funding commitments.

### When to raise

Not before five design partners and one named logo. Below that you are pitching
vapourware with good documentation, which is exactly what the market punished this
project for at 1.0.

Raise **$1.5-2.5M at a $5-8M post**. That funds 18 months of the corpus and the
entity, and it is priced off design partners rather than stars. The VC's ceiling was
$2.5M at $100k ARR — clear that with a corpus standard in hand or accept you are
building the good project, not the company.

### The co-founder you are missing

The out-of-band approval channel is **the** control that survives a fully
compromised agent, because when the agent is fully compromised the engine is
inside the compromised process. Everyone needs it. Nobody wants to build it:
it is number-portability, SMS-A2P registration, and per-country telecom compliance.

If you know anyone who has done carrier procurement, that is the conversation. It is
the highest-value single hire or co-founder available to you, and it is the one
capability the funded competitors cannot buy quickly.

---

## 6. What not to do

- **Do not claim uniqueness.** `hoophq/fence` exists. Outerlimit raised $16M in
  September for "Zero Trust on AI Agent Actions" with cryptographic composite
  identity — which beats your single-use HMAC token. An investor finds that in one
  search. It kills you.
- **Do not lead with tokens.** Outerlimit's composite identity is better.
- **Do not put a paid tier on the engine.** It caps the funnel and it is the same
  fiction we deleted yesterday.
- **Do not publish $624M as your TAM.** Two analysts disagree by 51% on the same
  year, and the arithmetic shows the CAGR was the input and the endpoint was
  back-filled. The defensible number is boring: **$375M of venture capital went
  into this category in twelve months.** Smaller, and true.
- **Do not sell the parser.** Table stakes has arrived. Table stakes is the worst
  possible place for a differentiator: buyers will not pay for it, competitors copy
  it in a sprint, and users get it free.
- **Do not accept an on-prem or air-gapped customer before month six.** The VC named
  this the specific death sentence: it ends your distribution, ends the engine's
  improvement loop, and converts a company into a deprecation-schedule consulting
  practice with equity risk and no exit.

---

## 7. The one thing worth taking from today

The competitor's memo, assessing whether you are a threat, ended with this:

> *"They can publish a rigorous limitation list about their own product, name their
> own weaknesses, and be trusted more for it. We cannot — our credibility is
> structurally tied to not having weaknesses, so we cannot be as candid, and
> candidness is what wins technical evaluators."*

A funded company structurally cannot say "this control does not decode base64"
without a remediation commitment attached. You can. That is a real moat against
capital, and it is the reason the GuardFall rewrite was worth doing even though it
cost you a day and cost the repo its cleanest story.

**Candour, at speed, in public, is the only genuinely defensible thing you have
that $16M cannot buy.** Everything else in this plan is execution. That part is
positioning, and you already own it.