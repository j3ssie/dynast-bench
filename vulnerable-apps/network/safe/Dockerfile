FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates openssl netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json simulator.mjs entrypoint.sh internal-sink.mjs ./
COPY tls ./tls
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000 80 443 8443 22 2222 21 25 8080 31337 23 8000 5432 6379 6380 27017 9200 9300 11211 15672 8081 9000 9001 161/udp
HEALTHCHECK --interval=10s --timeout=5s --retries=12 --start-period=5s \
  CMD if [ "$ROLE" = "scanner" ]; then curl -sf http://127.0.0.1:${NETMETA_PORT:-3000}/api/_verify/health >/dev/null; else exit 0; fi
CMD ["/app/entrypoint.sh"]
