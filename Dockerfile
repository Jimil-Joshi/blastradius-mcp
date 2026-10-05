# Multi-stage production build for BlastRadius MCP Server
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/
COPY tests/ ./tests/
RUN npm run build
RUN npm prune --production

FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Create unprivileged runtime user
RUN addgroup -S mcp && adduser -S mcp -G mcp
USER mcp

EXPOSE 3000

ENTRYPOINT ["node", "dist/src/index.js"]
