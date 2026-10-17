# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY --from=dynast-src /src/go.mod /src/go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
COPY --from=dynast-src /src/ .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -o /out/golang-app .

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/golang-app /app/golang-app
COPY --from=dynast-src /src/entrypoint.sh /app/entrypoint.sh
COPY --from=dynast-src /src/internal-sink.mjs /app/internal-sink.mjs
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=60s \
  CMD curl -sf http://localhost:3000/api/_verify/health || exit 1
CMD ["/app/entrypoint.sh"]
