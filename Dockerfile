# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Production
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist

# Expose the default port
EXPOSE 3000

# Set NODE_ENV to production
ENV NODE_ENV=production

# Liveness probe: hit /health on the node's own PORT (default 3000). Uses Node's
# built-in global fetch (Node 20) so no curl/wget dependency is needed on Alpine.
# Marks the container unhealthy on crash-hang (process alive but not serving) — the
# autoheal sidecar (docker-compose) then restarts it. Exit 0 = healthy, 1 = unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Run the application
CMD ["node", "dist/main.js"]
