# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM node:22-slim AS deps
WORKDIR /app
COPY --from=dynast-src /src/package.json /src/tsconfig.json ./
RUN --mount=type=cache,target=/root/.npm npm install
COPY --from=dynast-src /src/src ./src
RUN npm run build
RUN --mount=type=cache,target=/root/.npm npm prune --omit=dev

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=dynast-src /src/package.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/dist ./dist
COPY --from=dynast-src /src/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=30s \
  CMD node -e "fetch('http://127.0.0.1:3000/api/_verify/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["/app/entrypoint.sh"]
