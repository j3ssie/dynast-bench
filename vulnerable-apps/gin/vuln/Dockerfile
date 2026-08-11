FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -o /out/gin-app .

# The note-preview page sanitises with DOMPurify, so the real library has to be
# in the image rather than a hand-rolled stand-in. Pinned exactly: the bug that
# sits next to it is about what survives sanitisation, which is a property of a
# specific version.
FROM node:22-slim AS webvendor
WORKDIR /vendor
RUN --mount=type=cache,target=/root/.npm \
    npm install --omit=dev --no-audit --no-fund dompurify@3.2.4

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl imagemagick chromium fonts-liberation \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/gin-app /app/gin-app
COPY --from=webvendor /vendor/node_modules/dompurify/dist/purify.min.js /app/static/purify.min.js
COPY entrypoint.sh /app/entrypoint.sh
COPY internal-sink.mjs /app/internal-sink.mjs
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=60s \
  CMD curl -sf http://localhost:3000/api/_verify/health || exit 1
CMD ["/app/entrypoint.sh"]
