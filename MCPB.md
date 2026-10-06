# MCPB bundle

`manifest.json` describes this repo as an MCPB bundle (formerly DXT), which is
how a stdio MCP server is published to Smithery today. Smithery's current
publish flow accepts exactly two paths: **URL** (a server you host behind
Streamable HTTP) and **Local** (an `.mcpb` file built by `mcpb pack`). There is
no `smithery.yaml` in that flow, so the old one was deleted rather than left to
claim support that no longer exists.

Spec followed: https://raw.githubusercontent.com/modelcontextprotocol/mcpb/main/MANIFEST.md
(`manifest_version` `0.3`, spec last updated 2025-12-02).

## Notes on expressing this server in the spec

- Node `>=22.0.0` is declared as `compatibility.runtimes.node`, which is the
  exact key the spec defines. `compatibility.claude_desktop` is left out
  because there is no verified minimum client version to claim.
- `BLAST_RADIUS_SIGNING_KEY` and `BLAST_RADIUS_AUDIT_KEY` are exposed as
  `user_config` entries of `type: "string"` with `sensitive: true`, mapped into
  `server.mcp_config.env` via `${user_config.KEY}` — the mechanism the spec
  documents for secrets. Both are optional: unset, the server generates an
  ephemeral per-process key, which means approval tokens do not survive a
  restart and earlier audit entries stop verifying.
- The `--policy <file>` CLI flag is expressed the only way the spec allows: a
  `user_config` entry of `type: "file"` substituted into
  `server.mcp_config.args` as `--policy=${user_config.policy_file}`. The spec has
  no way to declare an argument that is *absent* when unset, so when no policy
  file is chosen the client substitutes an empty value and the argument arrives
  as `--policy=`. The server's own arg parser only matches the exact token
  `--policy`, so that form is ignored and the built-in policy profiles are used.
  That behaviour is verified by reading `src/index.ts`, not by running it.
- `privacy_policies` is an empty array: the server opens no sockets and sends
  nothing to any external service, first- or third-party.
- No icon is declared. The spec accepts a bundled PNG or an `https://` URL, and
  this repo has no icon asset.

## Building the bundle

Requires Node `>=22`. The MCPB CLI is intentionally **not** a project
dependency; it is fetched on demand by the `bundle` script so it stays out of
the normal dependency tree.

```bash
npm run bundle
```

That runs `tsc`, prunes to production dependencies, and packs the directory:

```
npm run build && npm prune --omit=dev && npx --yes @anthropic-ai/mcpb@2.1.2 pack . blastradius-mcp.mcpb
```

Output is `blastradius-mcp.mcpb` in the repo root. That file is the artifact
uploaded to Smithery under the Local path.

Note that `npm prune --omit=dev` removes devDependencies from `node_modules`, so
run `npm ci` afterwards to restore a working dev environment.