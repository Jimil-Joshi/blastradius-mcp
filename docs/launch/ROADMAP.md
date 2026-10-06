# BlastRadius MCP — Roadmap and Business Model

Internal document. Not marketing copy, and not for the repo. Its job is to keep
the OSS core and the commercial plan from contradicting each other.

---

## The core tension, stated honestly

You have two audiences with opposite incentives.

**Open source** earns stars, contributors, credibility, and inbound. That is what
gets an investor's first meeting. Stars are the only adoption metric that a solo
founder can move in a week without a sales team.

**SaaS** earns revenue. An Apache-2.0 repository cannot be metered, gated, or
resold, and pretending otherwise is the licensing fiction we just removed.

The way out is the standard one, and it is the only structure that satisfies both:
**the engine stays Apache-2.0 and completely free. The business is the operational
layer around it.**

---

## What stays free, permanently

The engine is not the moat. The moat is knowing what real agents actually try to do
in production, which only happens by watching traffic nobody will hand you for free.

| Component | License | Why it stays free |
| :--- | :--- | :--- |
| `blastradius-mcp` engine | Apache-2.0 | Adoption is the funnel. Gating it caps the funnel. |
| 21 detection signatures | Apache-2.0 | Forkability is a feature. A blocked rule set gets patched around. |
| Shell resolver | Apache-2.0 | The technique should spread. Being the reference implementation is worth more. |
| Sequence detector | Apache-2.0 | Adoption here is what surfaces the attacks nobody has seen yet. |
| DLP patterns | Apache-2.0 | Same reasoning. |
| Audit ledger format | Apache-2.0 | A standard adopted by many is a standard. |

**Never gate the engine. Never ship a broken free tier.** A security tool that
locks its detection behind a tier is a security tool nobody installs.

---

## What gets built for money

Three products, in the order they become sellable. Each is the same engine, and the
argument for each is "you cannot run this yourself at scale".

### 1. BlastRadius Cloud — the shared control plane

The local engine decides on a single call in isolation. It cannot see the other 400
calls your fleet made in the last ten minutes, and it cannot tell you that a
different service is doing the thing this one was blocked from doing.

That is the gap, and it is the one the research says is the next real control.

- Fleet-wide sequence detection across every agent, session, and service
- Continuous rule updates written by people who watch real attack traffic
- Central policy, versioned and auditable, pushed to every agent
- SIEM export. This is the honest answer to the "you promised Splunk" gap: it is a
  paid feature because it is a managed pipeline, not because it is a fake.
- Team accounts, SSO, RBAC, approval workflows with real identity behind them

**Why this is defensible when `fence` is free.** `fence` guards one machine's
shell, and it says so plainly. It is self-protection. Nobody has the cross-fleet
sequence picture, because that requires watching traffic, and watching traffic is a
service, not a library.

### 2. Threat Intelligence

Rules derived from real traffic, shipped continuously.

The honest position: the 21 signatures are good. They are also a snapshot of what
public research has documented. What makes a rule set genuinely ahead is knowing what
attackers are actually trying, which is exactly what a fleet deployment sees and
a library never will.

This is the product that compounds. Every customer makes the rules better for
everyone, and open source keeps the baseline strong enough to keep everyone using it.

### 3. Enterprise

- Air-gapped deployment, no egress
- Custom signature packs for your internal tooling
- The SLA and the support contract
- Commercial support for the resolution layer if a bypass is found

---

## What is deliberately not a product

**Do not rebuild a hosted MCP registry.** It is owned by incumbents and they will
out-distribute you. Do not build agent orchestration, do not build an agent
framework, and do not build a hosted agent. The bet is that the security layer stays
valuable no matter which agent wins.

**Do not compete on model-based detection.** The rule engine is deterministic,
explainable, has no latency, costs nothing per call, and produces a verdict an
auditor can read. That is a feature against competitors. An LLM classifier can be a
complement, never the hard BLOCK path, because a prompt-injected call must not be
able to talk its way past the gate.

---

## The credibility constraint on all revenue

An investor will ask whether the open source core is deliberately hobbled to sell
the cloud. The answer has to be verifiably no.

- The free engine must be complete enough that a competent team runs production on
  it and never feels the pull to upgrade for correctness reasons.
- The paid layer must be faster to adopt, not more correct.
- The changelog must keep showing OSS features shipping without a paywall.

The moment a bug fix is gated, the whole enterprise thesis dies, because nobody
deploys security tooling they cannot patch themselves.

---

## Metrics that matter, in order

| Metric | Why it is first or late |
| :--- | :--- |
| Weekly npm downloads | The only honest adoption number. Not stars. Stars are marketing. |
| GitHub issues from non-author accounts | The strongest early signal that a real team is using it. |
| Contributions from outside | Provenance, not popularity. |
| Stars | Fine to publicise, poor to optimise. |
| Revenue | Irrelevant until one of the above is working. |

Report installs and external issues to investors. Reporting stars reads as needing
the stars to be the story.

---

## Concrete next steps

1. **Push and publish.** Nothing ships until the fixes are on `main` and
   `npm publish` is live. Every directory listing reads the published package.
2. **Get to 500 stars before pitching.** Below that the pitch is a hobby. Above it,
   it is traction. Comments on other people's posts are the lever, which is why
   they are being paced rather than blasted.
3. **Find five teams running it in production** and ask what broke. That
   conversation is the seed of the entire commercial roadmap and of the threat
   intelligence product. It is worth more than any amount of feature work.
4. **Write the detection rules doc publicly.** A page per attack pattern with real
   examples earns search traffic and inbound, and it is the same content a
   prospect would use to evaluate a vendor.
5. **Only then build the control plane.** Its design comes from what those five
   teams ask for, not from a guess made now.