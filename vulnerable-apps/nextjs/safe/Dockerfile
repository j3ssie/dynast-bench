# Vulnerable variant. Build context is this folder (vuln/), so ../ground-truth
# is structurally outside the context and can never be baked into the image.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

ENV NEXT_TELEMETRY_DISABLED=1
# Dummy URL so a Prisma client constructed during `next build` never blocks on a
# real DB (all data-touching routes/pages are force-dynamic, so none query here).
ENV DATABASE_URL=postgresql://build:build@localhost:5432/build

WORKDIR /app
COPY package.json ./
RUN --mount=type=cache,target=/root/.npm npm install
COPY . .
RUN npx prisma generate
RUN npm run build

EXPOSE 3000
CMD ["sh", "/app/entrypoint.sh"]
