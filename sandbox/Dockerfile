FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    ca-certificates \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Create and grant app directory ownership to non-root user
WORKDIR /home/node/app
RUN chown -R node:node /home/node/app

# Drop root privileges
USER node

# Install Playwright
RUN npm install playwright-core@1.48.0

COPY --chown=node:node runner.js .

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "runner.js"]
