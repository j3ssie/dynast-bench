# Vulnerable variant. Build context is this folder (vuln/), so ../ground-truth
# is structurally outside the context and can never be baked into the image.

# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

ENV NEXT_TELEMETRY_DISABLED=1
# Dummy URL so a Prisma client constructed during `next build` never blocks on a
# real DB (all data-touching routes/pages are force-dynamic, so none query here).
ENV DATABASE_URL=postgresql://build:build@localhost:5432/build

WORKDIR /app
COPY --from=dynast-src /src/package.json ./
RUN --mount=type=cache,target=/root/.npm npm install
COPY --from=dynast-src /src/ .
RUN npx prisma generate
RUN npm run build

EXPOSE 3000
CMD ["sh", "/app/entrypoint.sh"]
