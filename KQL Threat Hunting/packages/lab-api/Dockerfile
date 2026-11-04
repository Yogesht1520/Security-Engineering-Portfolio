FROM node:22-alpine AS builder

WORKDIR /app

RUN npm install -g pnpm@12.16.1

COPY package.json pnpm-workspace.yaml ./
COPY packages/core/package.json ./packages/core/
COPY packages/datagen/package.json ./packages/datagen/
COPY packages/cli/package.json ./packages/cli/
COPY packages/lab-api/package.json ./packages/lab-api/

RUN pnpm install --frozen-lockfile=false

COPY . .

RUN pnpm --filter @huntbook/core build && \
    pnpm --filter @huntbook/datagen build && \
    pnpm --filter @huntbook/lab-api build

EXPOSE 3001

CMD ["node", "packages/lab-api/dist/index.js"]

