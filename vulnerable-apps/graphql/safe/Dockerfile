FROM node:22-slim AS deps
WORKDIR /app
COPY package.json tsconfig.json ./
RUN --mount=type=cache,target=/root/.npm npm install
COPY src ./src
RUN npm run build
RUN --mount=type=cache,target=/root/.npm npm prune --omit=dev

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/dist ./dist
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=30s \
  CMD node -e "fetch('http://127.0.0.1:3000/api/_verify/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["/app/entrypoint.sh"]
