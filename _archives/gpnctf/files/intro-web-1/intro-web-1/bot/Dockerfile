FROM node:22-alpine AS node_love

WORKDIR /app

COPY package*.json ./
RUN npm ci

FROM node:21-slim

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        chromium \
        fonts-liberation \
        libappindicator3-1 \
        libasound2 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxrandr2 \
        libxtst6 \
        xdg-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos "" bot
USER bot

WORKDIR /bot
RUN chown -R bot:bot /bot

COPY --from=node_love /app/node_modules ./node_modules

RUN npx puppeteer browsers install chrome

COPY app.mjs ./

CMD node app.mjs
