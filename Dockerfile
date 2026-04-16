# ── TitanControl-HMI Dockerfile ────────────────────────────
FROM node:20-alpine

# App directory
WORKDIR /app

# Install dependencies first (layer caching)
COPY package*.json ./
RUN npm install --production

# Copy source
COPY . .

# /data is the persistent volume for SQLite
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 1943

CMD ["node", "server.js"]
