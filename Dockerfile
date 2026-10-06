# blastradius-mcp — container image for the zero-trust MCP security server.
#
# What this image is:
#   A minimal, non-root runtime image for `blastradius-mcp`, a stdio-transport MCP
#   server that performs pre-execution blast-radius simulation, DLP redaction,
#   zero-trust policy enforcement, and hash-chained audit logging.
#
# How to wire it into an MCP client config (Claude Desktop / Cursor / VS Code):
#
#   {
#     "mcpServers": {
#       "blastradius": {
#         "command": "docker",
#         "args": ["run", "-i", "--rm", "--init", "blastradius-mcp:1.0.0"]
#       }
#     }
#   }
#
#   Note the flags:
#     -i       the MCP stdio transport needs stdin/stdout attached, or the server
#              will start and immediately see a closed pipe.
#     --rm     the audit ledger is appended to the container filesystem; keep the
#              container unless you want its records.
#     --init   proxy mode (`proxy --command "..."`) spawns a downstream child
#              process. Without an init process, PID 1 does not reap the zombies
#              that child leaves behind.
#
# Build:
#   docker build -t blastradius-mcp:1.0.0 .
#
# Inspect it (prints the CLI help and exits 0):
#   docker run --rm blastradius-mcp:1.0.0
#
# Run as a security server:
#   docker run -i --rm --init blastradius-mcp:1.0.0
#
# Run as a transparent proxy in front of another MCP server:
#   docker run -i --rm --init blastradius-mcp:1.0.0 \
#     proxy --command "npx -y @modelcontextprotocol/server-filesystem /workspace"

# ---------------------------------------------------------------------------
# Stage 1 — build the TypeScript sources.
# `dist/` is gitignored and both `main` and `bin` in package.json point into it,
# so the image must be built here; there is no prebuilt output to copy in.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Install from the lockfile first so the dependency layer is cached independently
# of source changes. Dev dependencies are required: TypeScript is the compiler.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — runtime. Production dependencies plus the compiled output only.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder --chown=node:node /app/dist ./dist

# The audit ledger is appended to the current working directory as
# blastradius-audit.jsonl, so the unprivileged runtime user needs write access
# to the directory itself. node_modules stays root-owned and read-only: the
# server only ever reads it.
RUN chown node:node /app

# A security tool must not ship a root container: the MCP server runs arbitrary
# policy checks against attacker-influenced input, so keep the default
# privileges stripped. The stock `node` user (uid 1000) is used as-is.
USER node

# Exec-form ENTRYPOINT below means node is PID 1 and receives SIGTERM directly,
# which lets the stdio transport shut down cleanly instead of being killed by
# Docker's default SIGKILL after the 10s grace period.
STOPSIGNAL SIGTERM

# Default to --help so a bare `docker run` is inspectable and exits 0.
# Clients override this by appending their own arguments (e.g. `proxy --command ...`).
ENTRYPOINT ["node", "dist/src/index.js"]
CMD ["--help"]
