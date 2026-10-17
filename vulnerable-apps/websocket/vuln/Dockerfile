# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=dynast-src /src/package.json /src/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY --from=dynast-src /src/ .
RUN npm run build && chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=60s CMD curl -sf http://localhost:3000/api/_verify/health || exit 1
CMD ["/app/entrypoint.sh"]
