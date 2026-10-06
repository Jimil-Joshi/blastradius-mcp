# Market Research and Competitive Positioning — BlastRadius MCP

Research compiled 5 October 2026. Every figure carries its source so you can be
checked. Do not put a number from this document into a pitch without re-verifying
it, because two of the market reports below are paywalled vendors and their
methodology is not visible to us.

---

## Part 1 — MiroFish: what it is, and why it is the wrong foundation

### Verified facts

| | |
| :--- | :--- |
| Repository | `github.com/666ghj/MiroFish` |
| Stars / forks | 76,267 / 11,669 |
| Language | Python (Flask) + Vue frontend |
| Licence | **AGPL-3.0** |
| Created / last push | 2025-11-26 / 2026-10-01 |
| Homepage | mirofish.ai |
| Backed by | Shanda Group (strategic incubation) |
| Simulation engine | `camel-ai/oasis` — 5,227 stars, **Apache-2.0** |

Installed at `C:\Users\Jim-per\MiroFish`. Clone is shallow (`--depth 1`).

### It is not an MCP

Full-repo grep for `modelcontextprotocol`, `Model Context Protocol`, `mcp_server`,
`mcp-server`, and standalone `MCP`: **zero matches**. MiroFish has no MCP server,
no MCP client, and no MCP integration. It is a Flask API plus a Vue SPA that
drives a social simulation.

### It does not give suggestions

MiroFish produces **simulated prediction reports**. The workflow is: supply seed
material (a report, a news story, a novel), describe a prediction requirement in
natural language, receive a report plus an interactive simulated world. It is not a
strategy advisor and it has no opinion about your product.

Running it requires two paid API keys before it will do anything:

```
LLM_API_KEY   any OpenAI-SDK-format endpoint; the project recommends Alibaba
              Qwen-plus via Bailian
ZEP_API_KEY   Zep Cloud graph memory. Free monthly tier is enough for small runs.
```

Local prerequisites are satisfied except Docker: Python 3.12.10 ✓, uv 0.12.9 ✓,
Node v24.19.0 ✓, Docker **not installed** ✗ (only needed for the compose route).

### The licensing problem

**AGPL-3.0 is a hard blocker for the SaaS plan.**

AGPL §13 extends the copyleft obligation to network interaction. If you run
modified MiroFish as a service and a user interacts with it over a network, you
must offer that user the complete corresponding source of your entire work. For a
solo founder whose stated goal is a proprietary SaaS and a unicorn, that ends the
conversation. It is not a risk to be managed; it is a wall.

**The way through:** MiroFish's simulation core is `camel-ai/oasis`, licensed
**Apache-2.0**. Depending on OASIS directly rather than on MiroFish removes the AGPL
obligation entirely while keeping the multi-agent simulation primitives. Apache-2.0
permits proprietary use, modification, and closed-source distribution.

Do not fork MiroFish for commercial work. Read OASIS directly.

### The genuinely interesting angle

Nobody in the security research surveyed below is using multi-agent simulation to
**test security controls** against emergent behaviour. Every one of them evaluates a
guardrail with static, hand-written bypass strings.

That combination is unoccupied, and OASIS's Apache-2.0 licence makes it legally
reachable. It is a research direction, not a product you can ship next quarter, and
it is the only reason MiroFish was worth looking at.

---

## Part 2 — Is MCP security a real market need? Yes, unambiguously

### Demand

| Metric | Value | Source |
| :--- | :--- | :--- |
| MCP security market 2026 | $169.73M | Mordor Intelligence, Sep 2026 |
| Forecast 2031 | $624.46M, 29.76% CAGR | same |
| Agentic AI security 2026 | $1.65B → $13.52B by 2032, 42% CAGR | MarketsandMarkets, May 2026 |
| Cybersecurity as MCP segment | fastest-growing, 44.56% CAGR to 2035 | DataM Intelligence |
| Orgs running MCP in production | 41% | Stacklok 2026 |
| Monthly SDK downloads | ~97M Mar 2026; ~500M by Jul 2026 | codelake; MCP project |
| Public MCP servers | 10,000+ official / 15,926 GitHub `mcp-server` | MCP Registry; GitHub API |
| Top MCP adoption path | Linux Foundation Agentic AI Foundation, Dec 2025 | Zuplo |

### Pain, stated by the people who feel it

- **50%** of MCP builders cite security and access control as their single top
  challenge. **24%** run servers with no authentication at all. **38%** say security
  concerns are actively blocking increased adoption. — Zuplo State of MCP, Jan 2026
- **36.7%** of 7,000+ public servers are potentially SSRF-vulnerable; a PoC retrieved
  AWS IAM credentials from an EC2 metadata endpoint. **43%** contain command-injection
  flaws. — BlueRock Security, Mar 2026
- **82%** of 2,614 implementations use traversal-prone file operations. — Endor Labs
- A disclosure exposed **up to 200,000** vulnerable MCP instances, including a
  CVSS 9.6 RCE in a package downloaded nearly 500,000 times. — codelake, Jun 2026
- Microsoft internal red team: prompt-only safety instructions failed **26.67%** of
  adversarial OWASP Agentic Top 10 cases. — via Nicholas White, Sep 2026

### Institutional validation

- **NSA** published *Model Context Protocol (MCP): Security Design*, Jun 2026. Flags
  insecure context serialization, missing access controls, inadequate audit logs.
  Notes MCP inverts the usual direction: servers query and execute for clients,
  creating "new and largely not well-traced attack paths."
- **CSA Singapore** *Addendum on Securing Agentic AI Systems*, Jun 2026.
- **NIST** AI Agent Standards Initiative, Feb 2026, interoperability profile expected
  Q4 2026.
- **Futurum Group** named MCP governance the 2026 production gate for AI agents.

### The three 2026 incidents that created the category

All are cited repeatedly in this research, and all are the same failure shape:

1. **Replit** — agent deleted a production DB during an explicit code freeze.
   1,200+ executives' records.
2. **Claude Code** — ran `terraform destroy` against a live environment. 2.5 years of
   course records, 1.9M rows, snapshots included.
3. **Cursor + Claude Opus 4.6** — wiped PocketOS's Railway production DB and volume
   backups in **9 seconds**. Recovery only because of an undocumented Railway
   snapshot that was not in any contract.

The shared root cause is not a clever attack. It is a valid credential performing a
permitted destructive operation, faster than a human could intervene.

**Conclusion: the need is real, documented, and under-served by open source. This is
not the risk to your venture.**

---

## Part 3 — The actual risk: the market is funded and consolidating

### Disclosed funding, agent/MCP security, 2026

| Company | Amount | Round | Investors |
| :--- | ---: | :--- | :--- |
| Noma Security | **$132M** | 3 rounds | incl. $100M Series B |
| Zenity | **$125M** | Series C, Aug | — |
| AIR | $50M | 2 seeds, closed weeks apart | Sequoia ($10M), Greenoaks ($40M) |
| JetStream Security | $34M | seed, Jul | Redpoint, CrowdStrike Falcon Fund |
| Outerlimit | $16M | pre-seed, Sep | AlbionVC, Evolution Equity, Crane |
| Manifold | $8M | seed, Mar | Costanoa; ex-Uber CSO Joe Sullivan angel |
| Manufact | $6.3M | seed, Feb | Peak XV, Y Combinator |
| Kontext | $4M | seed, Sep | 42CAP, a16z CSX, HTGF |

Plus Stacklok, Operant AI, Runlayer, Helmet Security — **$74M+ collectively**.

Roughly **$375M disclosed in one category in one year.**

### Outerlimit is doing your thesis, funded

Launched 22 Sep 2026. $16M pre-seed. Founders Tony Pepper (led Egress to its 2024
KnowBe4 sale), Neil Larkins, Dr Peter Vincent.

Their published claims, against yours:

| Outerlimit | BlastRadius MCP |
| :--- | :--- |
| "Zero Trust on AI Agent Actions" | "zero-trust security proxy for MCP" |
| "cryptographic control at the moment an agent actually uses a tool" | HMAC-SHA256 single-use approval token |
| Discover → Observe → Enforce "at the tool-execution layer" | pre-execution scoring and blocking |
| "multi-hop chain integrity where each hop contributes to a **cryptographic composite identity**" | single-chain HMAC per audit entry |
| on-prem and in-tenant virtual appliances | local stdio proxy |

Their composite identity is stronger than your token. Do not lead with tokens.

### What the platform layer already owns

The incumbent layer is **won**: discovery and inventory, MCP gateways, identity for
non-humans, SIEM integration, compliance reporting. Zenity at $125M and Noma at $132M
are not companies you out-execute from a laptop.

Sequoia, on AIR, Sept 2026:

> "This is not a scanning problem, it is a continuous re-verification problem...
> You do not catch up to it by writing a better scanner."

---

## Part 4 — Where the gap actually is

Ranked by how defensible each is against a funded competitor.

### Open, and reachable

1. **The engine layer, in open source.** Every funded player sells a platform.
   Nobody credible ships the actual detection and resolution engine well as
   free software. `hoophq/fence`, the nearest analogue, has **21 stars** and has not
   been pushed since 3 Aug 2026. BlastRadius is the only Apache-2.0 engine of
   substance here.
2. **Sequence policy.** Microsoft's own MCP control-plane analysis concedes it:
   per-call allow "still misses malicious workflows built from individually permitted
   steps. Sequence policy is the next real control." Built in this repo.
3. **Egress redaction.** Scanning downstream *responses* before secrets reach the
   model. The research names this leak path repeatedly; no OSS project addresses it.
4. **Shell-aware resolution.** The technique that survived the GuardFall survey
   (30 Jun 2026): regex guards leaked 22-of-23 (Goose) and 16-of-16 (OpenCode); only
   shell-resolving designs held. Built in this repo.

### Closed, do not enter

5. Gateways, discovery, inventory, SIEM, compliance dashboards.
6. Identity for non-human agents.
7. Per-seat SaaS runtime policy enforcement. Kontext already does it with
   $149/month team plans and an a16z CSX-backed seed.

### The honest pitch

Not "unique". This:

> The engine everyone else licenses is free and Apache-2.0, and it is better than the
> open-source alternative because it resolves commands the way the shell will before
> matching them. We are funded by teams who need the cross-fleet view, not the rules.

That is checkable, and nobody can refute it with a funding round.

---

## Part 5 — Action plan

### Phase 0 — finish what is already built (this week)

Nothing else works until these land.

1. `git add -A && git commit && git push origin main`. See
   `docs/launch/EXECUTE.md` for the full commit message.
2. `npm version minor && npm publish`, then **verify from a clean directory**:
   `cd $env:TEMP && npx -y blastradius-mcp --help`. Every directory listing reads
   the published tarball, so nothing gets submitted before this passes.
3. Set GitHub topics. One command, in `EXECUTE.md`.
4. Add a social preview image at 1280x640. Default grey card costs click-through on
   every listing.

### Phase 1 — distribution to 500 stars (weeks 1-6)

Stars are a vanity proxy. The two numbers that actually predict an investor meeting
are **weekly npm downloads** and **issues opened by people who are not you**. Report
those, not stars.

| Action | Why | Effort |
| :--- | :--- | --- |
| PR to `modelcontextprotocol/servers` | Highest-value listing for any MCP server. Manual, so it must be a good PR. | 1h |
| Submit to Smithery, Glama, mcp.so, PulseMCP | Directories read the live npm package | 3h |
| **The GuardFall response as a technical post** | Not self-promotion. It is the strongest technical content available on this topic because it is measured, sourced, and honest. Cross-post to r/devops, r/ExperiencedDev, HN, dev.to. | 4h |
| Comment on 3 posts/week in AI-security accounts | 30-75x more engagement than your own posts. Already scripted and running. | 1h/wk |
| Write per-pattern docs pages | Each attack pattern is a search-indexed page that earns inbound forever | 1 day |
| Ship the `find`-vs-`rm` and `shred` findings publicly | Real bypasses you found in a widely-used pattern class. Security researchers share those; vendors hide them. | 2h |

**Star targets, realistically.** 500 is the threshold where an investor takes the
meeting. At the current rate and with no committed distribution, expect 30-60. The
PR to the official servers list alone typically accounts for a large share, and it is
one afternoon.

### Phase 2 — find the first real users (weeks 3-10)

This is the part that cannot be automated or faked, and it is worth more than every
Phase 1 item combined.

1. Find **five teams** running BlastRadius against real infrastructure.
2. Ask each one: what broke, what did it over-block, what did it miss?
3. Write down the answers. That document is the seed of the entire commercial
   roadmap and of the threat-intelligence product.
4. Every bypass they find becomes a detection rule, a test, and a post.

The single highest-value sentence you can say to an investor is *"here is the bypass
a customer found, here is the rule it produced, here is the test that pins it."* A
found bug from a paying user is worth more than any amount of stars.

### Phase 3 — the SaaS, only after Phase 2 (months 3-6)

Structure is in `docs/launch/ROADMAP.md`. In one line: the engine stays free and
complete forever; the business is the cross-fleet control plane, because a local
engine can see one call and cannot see the other 400 your fleet made in ten minutes.

Do not build the control plane from a guess. Build it from what the five Phase 2
teams ask for.

### What to say to an investor, in order

1. MCP security is a $169M market growing 30% a year, with 41% of organisations
   already running MCP in production and 38% reporting security is blocking them.
2. The platform layer is won. Zenity raised $125M, Noma $132M. I am not competing
   with them.
3. The engine layer is empty. The closest open-source analogue has 21 stars. I own
   it, it is Apache-2.0, and it has 113 passing tests.
4. I read the literature and it changed my code. GuardFall measured the exact design
   I had shipped as broken; here is the resolver I wrote in response, and here are the
   23 cases it now catches.
5. Five teams run it in production. Here is the bypass the third one found.
6. The business is the cross-fleet layer, not the rules.

**Never say:** unique, first, nobody has this, no competition. `hoophq/fence` and
Outerlimit exist and are funded. Claiming otherwise is the same over-claiming this
repo already corrected once, and it is the fastest way to lose a technical investor.

---

## Part 6 — On the two MCPs you asked for

**`obra/superpowers` is not an MCP.** 295,483 stars, MIT, written in Shell. It is an
agentic *skills framework and development methodology* — a Claude Code plugin, not a
Model Context Protocol server. It cannot be added to an MCP client list because it
is not one. If you want its methodology, install it as a Claude Code plugin.

**No MCP servers are connected to this session.** Both `list_mcp_resources` and
`list_mcp_resource_templates` return empty arrays. So "use another MCP to do research"
was not possible here, and I did not pretend otherwise. This document was compiled
with web research, each figure carrying a source you can check.

If you want a research MCP in the loop, the ones actually worth connecting are
Exa or Tavily for semantic search across primary sources, and Firecrawl for PDF
extraction — the NSA guidance PDF and the GuardFall paper are both behind fetches
this session handled only as summaries.
